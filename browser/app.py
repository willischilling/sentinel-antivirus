"""Sentinel Browser: a private browser with Sentinel's protection built in.

The window is WinForms (through pythonnet), and everything in it is Microsoft
Edge's WebView2 engine, which ships with Windows and is kept patched by
Microsoft. The tab strip and address bar are an HTML page in their own
WebView2 on top; each tab is another WebView2 below; the shield, downloads and
menu panels open in a small popup window. The pages talk to this code with
postMessage.

Private by default: every window gets a fresh, temporary browser profile in
InPrivate mode, deleted when the window closes. No history, cookies, cache or
form data is kept.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

WV2_VERSION = "1.0.4191.47"


def _resources() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) / "browser" if base else Path(__file__).resolve().parent


RES = _resources()
LIB = RES / "lib"
WEB = RES / "web"
HOME = "https://sentinel.local/start.html"
TEMP_PREFIX = "sentinel-browser-"


def _load_clr():
    import clr

    clr.AddReference("System.Windows.Forms")
    clr.AddReference("System.Drawing")
    clr.AddReference(str(LIB / "Microsoft.Web.WebView2.Core.dll"))
    clr.AddReference(str(LIB / "Microsoft.Web.WebView2.WinForms.dll"))


def webview2_installed() -> bool:
    """The WebView2 runtime (part of Edge on Windows 10/11)."""
    import winreg

    key = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    for hive, path in ((winreg.HKEY_LOCAL_MACHINE, key), (winreg.HKEY_CURRENT_USER, key.replace("WOW6432Node\\", ""))):
        try:
            with winreg.OpenKey(hive, path) as k:
                if winreg.QueryValueEx(k, "pv")[0] not in ("", "0.0.0.0"):
                    return True
        except OSError:
            continue
    return False


def _clean_old_profiles():
    """Temporary profiles of earlier windows that couldn't be deleted on exit (files still in use)."""
    for old in Path(tempfile.gettempdir()).glob(TEMP_PREFIX + "*"):
        try:
            if time.time() - old.stat().st_mtime > 60:
                shutil.rmtree(old, ignore_errors=True)
        except OSError:
            pass


class Tab:
    _next = 1

    def __init__(self):
        self.id = Tab._next
        Tab._next += 1
        self.view = None
        self.core = None
        self.title = ""
        self.url = ""
        self.favicon = ""
        self.loading = False
        self.verdict = "safe"          # safe, caution, blocked
        self.reason = ""
        self.trackers = 0              # blocked on the current page
        self.upgraded_from = None      # the http:// address we moved to https://
        self.upgraded_to = None
        self.upgrade_nav = None        # the navigation id of that https:// attempt
        self.pending_url = None        # to open once the engine is ready
        self.new_window = None         # (args, deferral) for a popup opened by a page
        self.shown_url = None          # what the address bar shows on Sentinel's warning pages


class Browser:
    def __init__(self, start_url: str | None):
        from System import Uri  # noqa: F401  (loads the .NET types)
        from System.Drawing import Color, Size
        from System.Windows.Forms import DockStyle, Form, FormStartPosition, Panel
        from Microsoft.Web.WebView2.WinForms import WebView2

        from core import i18n, settings
        from browser import protection, strings

        i18n.set_language(settings.load().get("language"))
        self.t = strings.table()
        self.protection = protection
        self.trackers = protection.TrackerList()
        threading.Thread(target=self.trackers.refresh_if_old, daemon=True).start()
        self.opts = protection.options()
        self.tabs: dict[int, Tab] = {}
        self.order: list[int] = []
        self.active: int | None = None
        self.downloads = []
        self.session_allowed = set()   # hosts the person chose to open anyway
        self.http_allowed = set()      # hosts allowed without https
        self.stats = {"trackers": 0, "blocked": 0, "popups": 0}
        self.start_url = start_url

        self.form = Form()
        self.form.Text = "Sentinel Browser"
        self.form.Size = Size(1280, 820)
        self.form.MinimumSize = Size(640, 420)
        self.form.StartPosition = FormStartPosition.CenterScreen
        self.form.BackColor = Color.FromArgb(11, 17, 32)
        try:
            from System.Drawing import Icon

            self.form.Icon = Icon(str(RES / "icon.ico"))
        except Exception:
            pass
        self.content = Panel()
        self.content.Dock = DockStyle.Fill
        self.content.BackColor = Color.FromArgb(11, 17, 32)
        self.ui = WebView2()
        self.ui.Dock = DockStyle.Top
        self.ui.Height = 82
        self.ui.DefaultBackgroundColor = Color.FromArgb(15, 23, 42)
        self.form.Controls.Add(self.content)
        self.form.Controls.Add(self.ui)
        self.panel_form = None
        self.panel_view = None
        self.panel_kind = None
        self.data_dir = tempfile.mkdtemp(prefix=TEMP_PREFIX)
        self.form.Shown += self._on_shown
        self.form.FormClosed += self._on_closed
        self.form.HandleCreated += lambda s, e: _dark_title_bar(self.form)

    # ----------------------------------------------------------- startup --
    def _on_shown(self, sender, args):
        from Microsoft.Web.WebView2.Core import CoreWebView2Environment, CoreWebView2EnvironmentOptions

        CoreWebView2Environment.SetLoaderDllFolderPath(str(LIB))
        options = CoreWebView2EnvironmentOptions()
        # No background networking or sync; nothing phones home from the engine itself.
        options.AdditionalBrowserArguments = "--disable-background-networking --disable-sync --no-first-run"
        task = CoreWebView2Environment.CreateAsync(None, self.data_dir, options)
        self._wait(task, self._env_ready)

    def _wait(self, task, then):
        """Runs then(result) on the UI thread once a .NET Task finishes."""
        from System import Action

        def poll():
            while not task.IsCompleted:
                time.sleep(0.02)
            self.form.BeginInvoke(Action(lambda: then(task.Result)))

        threading.Thread(target=poll, daemon=True).start()

    def _env_ready(self, env):
        self.env = env
        self.ui.CoreWebView2InitializationCompleted += self._ui_ready
        self.ui.EnsureCoreWebView2Async(env)
        self.new_tab(self.start_url or HOME)  # here, not on the UI's "ready", which can arrive twice

    def _ui_ready(self, sender, args):
        from Microsoft.Web.WebView2.Core import CoreWebView2HostResourceAccessKind

        if getattr(self, "_ui_set_up", False):
            return  # the WinForms control can report "initialized" more than once
        self._ui_set_up = True
        core = self.ui.CoreWebView2
        core.SetVirtualHostNameToFolderMapping("sentinel-ui.local", str(WEB), CoreWebView2HostResourceAccessKind.Allow)
        core.Settings.AreDefaultContextMenusEnabled = False
        core.Settings.IsZoomControlEnabled = False
        core.Settings.AreDevToolsEnabled = False
        core.WebMessageReceived += self._on_ui_message
        core.Navigate("https://sentinel-ui.local/ui.html")

    # -------------------------------------------------------------- tabs --
    def new_tab(self, url=None, activate=True, new_window=None):
        from System.Drawing import Color
        from System.Windows.Forms import DockStyle
        from Microsoft.Web.WebView2.WinForms import WebView2

        tab = Tab()
        tab.pending_url = url or HOME
        tab.new_window = new_window
        tab.view = WebView2()
        tab.view.Dock = DockStyle.Fill
        tab.view.DefaultBackgroundColor = Color.White
        tab.view.Visible = False
        self.content.Controls.Add(tab.view)
        self.tabs[tab.id] = tab
        insert_at = self.order.index(self.active) + 1 if self.active in self.order and new_window else len(self.order)
        self.order.insert(insert_at, tab.id)
        options = self.env.CreateCoreWebView2ControllerOptions()
        options.IsInPrivateModeEnabled = True
        tab.view.CoreWebView2InitializationCompleted += lambda s, a, tab=tab: self._safely(self._tab_ready, tab)
        tab.view.KeyDown += lambda s, a: self._on_key(a)  # shortcuts the page didn't use
        tab.view.EnsureCoreWebView2Async(self.env, options)
        if activate:
            self.activate(tab.id)
        self.push_state()
        return tab

    def _tab_ready(self, tab):
        from Microsoft.Web.WebView2.Core import CoreWebView2HostResourceAccessKind, CoreWebView2WebResourceContext

        if tab.core is not None:
            return  # already set up (the control can report "initialized" more than once)
        core = tab.core = tab.view.CoreWebView2
        core.SetVirtualHostNameToFolderMapping("sentinel.local", str(WEB), CoreWebView2HostResourceAccessKind.Allow)
        s = core.Settings
        s.IsPasswordAutosaveEnabled = False
        s.IsGeneralAutofillEnabled = False
        s.IsStatusBarEnabled = True
        try:
            s.IsReputationCheckingRequired = True  # Microsoft SmartScreen, on top of Sentinel's checks
        except Exception:
            pass
        core.NavigationStarting += lambda snd, a: self._on_navigation(tab, a)
        core.FrameNavigationStarting += lambda snd, a: self._on_frame_navigation(tab, a)
        core.NavigationCompleted += lambda snd, a: self._on_navigation_done(tab, a)
        core.SourceChanged += lambda snd, a: self._on_source(tab)
        core.DocumentTitleChanged += lambda snd, a: self._on_title(tab)
        core.FaviconChanged += lambda snd, a: self._on_favicon(tab)
        core.HistoryChanged += lambda snd, a: self.push_state()
        core.NewWindowRequested += lambda snd, a: self._on_new_window(tab, a)
        core.DownloadStarting += lambda snd, a: self._on_download(tab, a)
        core.WebMessageReceived += lambda snd, a: self._on_page_message(tab, a)
        core.ContainsFullScreenElementChanged += lambda snd, a: self._on_fullscreen(tab)
        core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All)
        core.WebResourceRequested += lambda snd, a: self._on_request(tab, a)
        if tab.new_window:
            args, deferral = tab.new_window
            tab.new_window = None
            args.NewWindow = core
            args.Handled = True
            deferral.Complete()
        else:
            self.navigate(tab, tab.pending_url)

    def activate(self, tab_id):
        if tab_id not in self.tabs:
            return
        self.active = tab_id
        for tid, tab in self.tabs.items():
            tab.view.Visible = tid == tab_id
        tab = self.tabs[tab_id]
        tab.view.BringToFront()
        tab.view.Focus()
        self._update_title()
        self.push_state()

    def close_tab(self, tab_id):
        tab = self.tabs.pop(tab_id, None)
        if not tab:
            return
        index = self.order.index(tab_id)
        self.order.remove(tab_id)
        self.content.Controls.Remove(tab.view)
        tab.view.Dispose()
        if not self.order:
            self.form.Close()
            return
        if self.active == tab_id:
            self.activate(self.order[min(index, len(self.order) - 1)])
        self.push_state()

    def current(self) -> Tab | None:
        return self.tabs.get(self.active)

    def navigate(self, tab, url):
        if tab.core is None:
            tab.pending_url = url
            return
        try:
            tab.core.Navigate(url)
        except Exception:  # not a valid address after all: search for it instead
            tab.core.Navigate(self.protection.to_url(" " + url + " "))

    # ------------------------------------------------------- protection --
    def _on_navigation(self, tab, args):
        url = args.Uri
        tab.trackers = 0
        if url.startswith("https://sentinel.local/blocked.html"):
            return  # our warning page: keeps the verdict _show_page set
        if url.startswith(("https://sentinel.local/", "data:", "about:")):
            tab.verdict, tab.reason, tab.shown_url = "safe", "", None
            return
        tab.shown_url = None
        host = self.protection.host_of(url)
        if self.opts["https_only"] and host not in self.http_allowed:
            upgraded = self.protection.upgrade_to_https(url)
            if upgraded:
                args.Cancel = True
                tab.upgraded_from, tab.upgraded_to = url, upgraded
                tab.core.Navigate(upgraded)
                return
        if tab.upgraded_from and url == tab.upgraded_to:
            tab.upgrade_nav = args.NavigationId  # the one to watch: if it fails, there's no https version
        elif tab.upgraded_from:
            tab.upgraded_from = tab.upgrade_nav = None
        verdict = self.protection.check_site(url)
        if verdict.level == "blocked" and host not in self.session_allowed:
            args.Cancel = True
            self.stats["blocked"] += 1
            reason = self.t.get(verdict.key, "").format(**verdict.values) if verdict.key else ""
            self._show_page(tab, "blocked", url=url, host=host, reason=reason)
            self._log_block(host, reason)
            return
        tab.verdict = "caution" if verdict.level == "caution" else "safe"
        tab.reason = self.t.get(verdict.key, "").format(**verdict.values) if verdict.key else ""
        tab.loading = True
        self.push_state()

    def _on_frame_navigation(self, tab, args):
        """Embedded frames: a known-bad one is just dropped (no warning page for an ad frame)."""
        url = args.Uri
        if url.startswith(("http://", "https://")) and self.protection.check_site(url).level == "blocked":
            args.Cancel = True

    def _on_request(self, tab, args):
        if not self.opts["block_trackers"]:
            return
        from Microsoft.Web.WebView2.Core import CoreWebView2WebResourceContext

        if args.ResourceContext == CoreWebView2WebResourceContext.Document:
            return  # pages themselves are handled by the site check
        host = self.protection.host_of(args.Request.Uri)
        page = self.protection.host_of(tab.url)
        if self.trackers.blocks(host, page):
            args.Response = self.env.CreateWebResourceResponse(None, 403, "Blocked by Sentinel", "")
            tab.trackers += 1
            self.stats["trackers"] += 1
            self._schedule_state()

    def _on_navigation_done(self, tab, args):
        tab.loading = False
        if tab.upgrade_nav is not None and args.NavigationId == tab.upgrade_nav:
            original = tab.upgraded_from
            tab.upgraded_from = tab.upgrade_nav = None
            if not args.IsSuccess:
                self._show_page(tab, "nohttps", url=original, host=self.protection.host_of(original))
                return
        self.push_state()

    def _show_page(self, tab, kind, **values):
        """Sentinel's own warning pages, with their text in the hash (no server involved)."""
        t = self.t
        data = {"kind": kind, **values, "strings": {k: v for k, v in t.items() if k.startswith("page_")}}
        encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
        tab.verdict = "blocked" if kind == "blocked" else "caution"
        tab.reason = values.get("reason", "")
        tab.shown_url = values.get("url")  # the address bar shows what was stopped, not our page
        tab.core.Navigate(f"https://sentinel.local/blocked.html#{encoded}")
        self.push_state()

    def _on_page_message(self, tab, args):
        """Buttons on Sentinel's own pages (never trusted from any other site)."""
        if not tab.core.Source.startswith("https://sentinel.local/"):
            return
        msg = json.loads(args.TryGetWebMessageAsString() or "{}")
        cmd = msg.get("cmd")
        url = msg.get("url", "")
        if cmd == "proceed":
            self.session_allowed.add(self.protection.host_of(url))
            tab.core.Navigate(url)
        elif cmd == "http":
            self.http_allowed.add(self.protection.host_of(url))
            tab.core.Navigate(url)
        elif cmd == "back":
            if tab.core.CanGoBack:
                tab.core.GoBack()
                if tab.core.CanGoBack:
                    tab.core.GoBack()  # past the page that was blocked
            else:
                tab.core.Navigate(HOME)
        elif cmd == "search":
            tab.core.Navigate(self.protection.to_url(msg.get("q", "")))
        elif cmd == "stats":  # the start page
            strings = {k: v for k, v in self.t.items() if k.startswith("brw_")}
            tab.core.PostWebMessageAsJson(json.dumps({"type": "stats", **self.stats, "strings": strings}))

    def _log_block(self, host, reason):
        try:
            from core import activity

            activity.log(self.t["brw_log_blocked"].format(host=host, reason=reason), "threat")
        except Exception:
            pass

    # ----------------------------------------------------- page details --
    def _on_source(self, tab):
        tab.url = tab.core.Source
        self._update_title()
        self.push_state()

    def _on_title(self, tab):
        tab.title = tab.core.DocumentTitle
        self._update_title()
        self._schedule_state()

    def _on_favicon(self, tab):
        tab.favicon = tab.core.FaviconUri or ""
        self._schedule_state()

    def _update_title(self):
        tab = self.current()
        self.form.Text = f"{tab.title} - Sentinel Browser" if tab and tab.title else "Sentinel Browser"

    def _on_new_window(self, tab, args):
        if not args.IsUserInitiated:  # a page opening windows by itself: pop-up
            args.Handled = True
            self.stats["popups"] += 1
            self._schedule_state()
            return
        deferral = args.GetDeferral()
        self.new_tab(args.Uri, activate=True, new_window=(args, deferral))

    def _on_fullscreen(self, tab):
        from System.Windows.Forms import FormBorderStyle, FormWindowState

        full = tab.core.ContainsFullScreenElement
        self.ui.Visible = not full
        self.form.FormBorderStyle = getattr(FormBorderStyle, "None") if full else FormBorderStyle.Sizable
        self.form.WindowState = FormWindowState.Maximized if full else FormWindowState.Normal

    def _safely(self, func, *args):
        """.NET events swallow Python errors silently; record them in the crash log instead."""
        try:
            func(*args)
        except Exception:
            from core import crashlog

            crashlog.write("browser", *sys.exc_info())

    def _on_key(self, args):
        ctrl, shift = bool(args.Control), bool(args.Shift)
        key = int(args.KeyValue)
        command = None
        if ctrl and key == 0x54:      # T
            command = {"cmd": "new_tab"}
        elif ctrl and key == 0x57:    # W
            command = {"cmd": "close_tab", "id": self.active}
        elif ctrl and key == 0x4C:    # L
            command = {"cmd": "focus_address"}
        elif ctrl and key == 0x09:    # Tab
            command = {"cmd": "cycle", "step": -1 if shift else 1}
        if command:
            args.Handled = True
            self._handle(command)
        elif key == 0x74 or (ctrl and key == 0x52):  # F5, Ctrl+R
            args.Handled = True
            self._handle({"cmd": "reload"})
        elif args.Alt and key in (0x25, 0x27):       # Alt+Left / Alt+Right
            args.Handled = True
            self._handle({"cmd": "back" if key == 0x25 else "forward"})

    # -------------------------------------------------------- downloads --
    def _on_download(self, tab, args):
        op = args.DownloadOperation
        args.Handled = True  # our downloads panel instead of Edge's
        item = {"id": len(self.downloads) + 1, "name": Path(args.ResultFilePath).name, "path": args.ResultFilePath,
                "state": "downloading", "received": 0, "total": int(op.TotalBytesToReceive or 0), "op": op}
        self.downloads.insert(0, item)
        op.BytesReceivedChanged += lambda s, a: self._download_progress(item)
        op.StateChanged += lambda s, a: self._download_state(item)
        self.open_panel("downloads", None)
        self.push_state()

    def _download_progress(self, item):
        item["received"] = int(item["op"].BytesReceived)
        item["total"] = int(item["op"].TotalBytesToReceive or 0)
        self._schedule_state()

    def _download_state(self, item):
        from Microsoft.Web.WebView2.Core import CoreWebView2DownloadState

        state = item["op"].State
        if state == CoreWebView2DownloadState.Completed:
            item["state"] = "scanning"
            item["path"] = item["op"].ResultFilePath
            threading.Thread(target=self._scan_download, args=(item,), daemon=True).start()
        elif state == CoreWebView2DownloadState.Interrupted:
            item["state"] = "failed"
        self.push_state()

    def _scan_download(self, item):
        from System import Action

        verdict, detail = "safe", ""
        try:
            from core import quarantine, scanner

            result = scanner.scan_file(Path(item["path"]))
            if result.verdict == "signature_match":
                quarantine.quarantine_file(Path(item["path"]), result.signature_name)
                verdict, detail = "threat", result.signature_name
                self._log_block(item["name"], result.signature_name)
            elif result.verdict == "suspicious":
                verdict, detail = "suspicious", "; ".join(result.heuristic_flags[:2])
        except Exception as e:
            verdict, detail = "unscanned", str(e)
        item["state"], item["detail"] = verdict, detail
        self.form.BeginInvoke(Action(self.push_state))

    # ----------------------------------------------------------- panels --
    def open_panel(self, kind, rect):
        """The shield, downloads or menu panel, in a small popup window under its button."""
        from System.Drawing import Color, Point, Size
        from System.Windows.Forms import DockStyle, Form, FormBorderStyle, FormStartPosition
        from Microsoft.Web.WebView2.WinForms import WebView2

        self.panel_kind = kind
        if self.panel_form is None:
            f = Form()
            f.FormBorderStyle = getattr(FormBorderStyle, "None")
            f.ShowInTaskbar = False
            f.StartPosition = FormStartPosition.Manual
            f.BackColor = Color.FromArgb(21, 31, 51)
            f.Owner = self.form
            view = WebView2()
            view.Dock = DockStyle.Fill
            view.DefaultBackgroundColor = Color.FromArgb(21, 31, 51)
            f.Controls.Add(view)
            f.Deactivate += lambda s, a: f.Hide()
            self.panel_form, self.panel_view = f, view

            def ready(s, a):
                from Microsoft.Web.WebView2.Core import CoreWebView2HostResourceAccessKind

                if getattr(view, "_set_up", False):
                    return
                view._set_up = True
                core = view.CoreWebView2
                core.SetVirtualHostNameToFolderMapping("sentinel-ui.local", str(WEB),
                                                       CoreWebView2HostResourceAccessKind.Allow)
                core.Settings.AreDefaultContextMenusEnabled = False
                core.Settings.AreDevToolsEnabled = False
                core.WebMessageReceived += self._on_ui_message
                core.NavigationCompleted += lambda s2, a2: self.push_state()
                core.Navigate("https://sentinel-ui.local/panel.html")

            view.CoreWebView2InitializationCompleted += ready
            view.EnsureCoreWebView2Async(self.env)
        scale = self.form.DeviceDpi / 96.0
        width, height = int(360 * scale), int({"shield": 330, "downloads": 360, "menu": 330}[kind] * scale)
        if rect:
            anchor = self.ui.PointToScreen(Point(int((rect["right"]) * scale) - width, int(rect["bottom"] * scale) + 4))
        else:  # e.g. a download started: under the right end of the toolbar
            anchor = self.ui.PointToScreen(Point(self.ui.Width - width - int(12 * scale), self.ui.Height))
        self.panel_form.TopMost = self.form.TopMost  # stays above the window even if it's always-on-top
        self.panel_form.Location = anchor
        self.panel_form.Size = Size(width, height)
        self.panel_form.Show()
        self.panel_form.Activate()
        self.push_state()

    # --------------------------------------------------------- messages --
    def _on_ui_message(self, sender, args):
        try:
            self._handle(json.loads(args.TryGetWebMessageAsString() or "{}"))
        except Exception:
            from core import crashlog

            crashlog.write("browser message", *sys.exc_info())

    def _handle(self, msg):
        cmd = msg.get("cmd")
        tab = self.current()
        if cmd == "ready":
            self.ui.CoreWebView2.PostWebMessageAsJson(json.dumps({"type": "strings", "strings": self.t}))
            self.push_state()
        elif cmd == "panel_ready" and self.panel_view:
            self.panel_view.CoreWebView2.PostWebMessageAsJson(json.dumps({"type": "strings", "strings": self.t}))
            self.push_state()
        elif cmd == "navigate" and tab:
            self.navigate(tab, self.protection.to_url(msg.get("text", "")))
        elif cmd == "new_tab":
            self.new_tab(HOME)
            self._focus_address()
        elif cmd == "close_tab":
            self.close_tab(msg.get("id", self.active))
        elif cmd == "activate":
            self.activate(msg.get("id"))
        elif cmd == "cycle" and self.order:
            index = (self.order.index(self.active) + msg.get("step", 1)) % len(self.order)
            self.activate(self.order[index])
        elif cmd in ("back", "forward", "reload", "stop", "home") and tab and tab.core:
            {"back": lambda: tab.core.CanGoBack and tab.core.GoBack(),
             "forward": lambda: tab.core.CanGoForward and tab.core.GoForward(),
             "reload": tab.core.Reload, "stop": tab.core.Stop,
             "home": lambda: tab.core.Navigate(HOME)}[cmd]()
        elif cmd == "focus_address":
            self._focus_address()
        elif cmd == "panel":
            self.open_panel(msg.get("kind"), msg.get("rect"))
        elif cmd == "close_panel" and self.panel_form:
            self.panel_form.Hide()
        elif cmd == "toggle":
            name = msg.get("name")
            if name in ("block_trackers", "https_only"):
                self.opts[name] = not self.opts[name]
                self.protection.set_option(name, self.opts[name])
                if tab and tab.core:
                    tab.core.Reload()
            self.push_state()
        elif cmd == "open_download":
            item = self._download(msg.get("id"))
            if item and item["state"] == "safe":
                os.startfile(item["path"])
        elif cmd == "show_download":
            item = self._download(msg.get("id"))
            if item and Path(item["path"]).exists():
                subprocess.Popen(["explorer.exe", "/select,", item["path"]])
        elif cmd == "open_sentinel":
            _open_sentinel()
            if self.panel_form:
                self.panel_form.Hide()
        elif cmd == "wipe":
            self.form.Close()  # closing is what wipes a private session
        elif cmd == "zoom" and tab and tab.core:
            tab.view.ZoomFactor = max(0.25, min(4.0, tab.view.ZoomFactor + msg.get("step", 0.1)))

    def _download(self, item_id):
        return next((d for d in self.downloads if d["id"] == item_id), None)

    def _focus_address(self):
        self.ui.Focus()
        self.ui.CoreWebView2.PostWebMessageAsJson(json.dumps({"type": "focus"}))

    _state_pending = False

    def _schedule_state(self):
        """Many events (tracker blocks, download progress) come in bursts: send at most ~8 updates a second."""
        if self._state_pending:
            return
        self._state_pending = True
        from System.Windows.Forms import Timer

        timer = Timer()
        timer.Interval = 120

        def fire(s, a):
            timer.Stop()
            timer.Dispose()
            self._state_pending = False
            self.push_state()

        timer.Tick += fire
        timer.Start()

    def push_state(self):
        tab = self.current()
        state = {
            "type": "state",
            "tabs": [{"id": t.id, "title": t.title or self.protection.display_url(t.url) or self.t["brw_tab_new"],
                      "favicon": t.favicon, "loading": t.loading, "verdict": t.verdict}
                     for t in (self.tabs[i] for i in self.order)],
            "active": self.active,
            "url": (self.protection.display_url(tab.shown_url or tab.url)) if tab else "",
            "secure": bool(tab and tab.url.startswith("https://")),
            "sentinel_page": bool(tab and (not tab.url or tab.url.startswith(("https://sentinel.local/", "about:")))
                                  and not tab.shown_url),
            "verdict": tab.verdict if tab else "safe",
            "reason": tab.reason if tab else "",
            "host": self.protection.host_of(tab.shown_url or tab.url) if tab else "",
            "trackers": tab.trackers if tab else 0,
            "can_back": bool(tab and tab.core and tab.core.CanGoBack),
            "can_forward": bool(tab and tab.core and tab.core.CanGoForward),
            "loading": bool(tab and tab.loading),
            "stats": self.stats,
            "opts": self.opts,
            "panel": self.panel_kind,
            "downloads": [{k: v for k, v in d.items() if k != "op"} for d in self.downloads[:12]],
            "downloading": sum(1 for d in self.downloads if d["state"] in ("downloading", "scanning")),
        }
        payload = json.dumps(state)
        for view in (self.ui, self.panel_view):
            try:
                if view is not None and view.CoreWebView2 is not None:
                    view.CoreWebView2.PostWebMessageAsJson(payload)
            except Exception:
                pass

    # ------------------------------------------------------------- close --
    def _on_closed(self, sender, args):
        for tab in list(self.tabs.values()):
            try:
                tab.view.Dispose()
            except Exception:
                pass
        try:
            self.ui.Dispose()
            if self.panel_view:
                self.panel_view.Dispose()
        except Exception:
            pass
        data_dir = self.data_dir

        def wipe():  # the engine's processes take a moment to let go of the profile
            for _ in range(40):
                shutil.rmtree(data_dir, ignore_errors=True)
                if not Path(data_dir).exists():
                    return
                time.sleep(0.25)

        wipe()


def _dark_title_bar(form):
    try:
        import ctypes

        value = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(int(form.Handle.ToInt64()), 20, ctypes.byref(value),
                                                   ctypes.sizeof(value))
    except Exception:
        pass


def _open_sentinel():
    exe = Path(sys.executable).resolve().parent.parent / "app" / "Sentinel.exe"
    if getattr(sys, "frozen", False) and exe.exists():
        subprocess.Popen([str(exe)])


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    start_url = next((a for a in argv if not a.startswith("-")), None)
    if not webview2_installed():
        import ctypes

        from core import i18n, settings
        from browser import strings

        i18n.set_language(settings.load().get("language"))
        ctypes.windll.user32.MessageBoxW(None, strings.table()["brw_no_webview2"], "Sentinel Browser", 0x40)
        return 1
    _clean_old_profiles()
    _load_clr()
    from System.Threading import ApartmentState, Thread, ThreadStart
    from System.Windows.Forms import Application

    result = {}

    def run():
        Application.EnableVisualStyles()
        browser = Browser(start_url)
        result["browser"] = browser
        Application.Run(browser.form)

    thread = Thread(ThreadStart(run))
    thread.SetApartmentState(ApartmentState.STA)  # WinForms and WebView2 need a single-threaded apartment
    thread.Start()
    thread.Join()
    return 0
