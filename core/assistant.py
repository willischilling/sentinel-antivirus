"""Ask Sentinel's AI: a small open model (Qwen3 4B, Apache 2.0) that runs
entirely on this PC through llama.cpp. No account, no API key, and nothing
typed leaves the computer.

The model (~2.5 GB) is downloaded once, on request, from a pinned Hugging
Face revision and checked against its SHA-256 before use. It's loaded on the
first question and unloaded after a few idle minutes to give the memory back.
"""
import hashlib
import os
import threading
import time
import urllib.request
from pathlib import Path

from . import i18n, paths

MODEL_FILE = "Qwen3-4B-Q4_K_M.gguf"
MODEL_URL = ("https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/"
             "bc640142c66e1fdd12af0bd68f40445458f3869b/" + MODEL_FILE)
MODEL_SHA256 = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
MODEL_SIZE = 2_497_280_256
MODEL_DIR = paths.DATA_DIR / "models"
MODEL_PATH = MODEL_DIR / MODEL_FILE
IDLE_UNLOAD_SECONDS = 300
MAX_TURNS = 6  # earlier messages are dropped to keep answers fast
USER_AGENT = "Sentinel-Antivirus/1.0"

SYSTEM_PROMPT = """You are Ask Sentinel, the scam checker built into the Sentinel Antivirus app for Windows.
People paste messages, emails, links or security questions. Your job:
1. Start with a one-line verdict: "Likely a scam", "Suspicious", "Looks safe" or "Can't tell".
2. Give the 2-4 most important reasons, as short bullet points.
3. End with what to do next, in one or two sentences.
Rules:
- Be short, plain and friendly. The reader may be a kid or someone who isn't technical.
- Built-in check results are facts from Sentinel's link lists and rules. Trust them over your own guesses about a link.
- Never tell someone to share a password, code, or payment. Never invent websites, phone numbers or facts.
- If you're not sure, say so and suggest checking through the company's official app or website directly.
- For questions that aren't about safety online, answer briefly and steer back to staying safe.
Reply in {language}."""


def installed() -> bool:
    return MODEL_PATH.is_file() and MODEL_PATH.stat().st_size == MODEL_SIZE


def engine_available() -> bool:
    try:
        import llama_cpp  # noqa: F401
        return True
    except (ImportError, OSError):
        return False


def download(progress=lambda done, total: None, cancel=lambda: False):
    """Downloads and verifies the model. Raises on failure or a checksum mismatch.
    Resumes a partial download."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    part = MODEL_PATH.with_suffix(".part")
    start = part.stat().st_size if part.exists() else 0
    headers = {"User-Agent": USER_AGENT}
    if start:
        headers["Range"] = f"bytes={start}-"
    request = urllib.request.Request(MODEL_URL, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        if start and response.status != 206:  # server ignored the range: start over
            start = 0
        with open(part, "ab" if start else "wb") as f:
            done = start
            while chunk := response.read(1 << 20):
                if cancel():
                    raise RuntimeError("cancelled")
                f.write(chunk)
                done += len(chunk)
                progress(done, MODEL_SIZE)
    digest = hashlib.sha256()
    with open(part, "rb") as f:
        while chunk := f.read(1 << 22):
            digest.update(chunk)
    if digest.hexdigest() != MODEL_SHA256:
        part.unlink(missing_ok=True)
        raise RuntimeError("the download was damaged (checksum mismatch); please try again")
    os.replace(part, MODEL_PATH)


def delete_model():
    MODEL_PATH.unlink(missing_ok=True)
    MODEL_PATH.with_suffix(".part").unlink(missing_ok=True)


class Assistant:
    """One chat. ask() streams tokens to on_token from a worker thread."""

    _llm = None
    _lock = threading.Lock()
    _last_used = 0.0

    def __init__(self):
        self.history: list[dict] = []

    def reset(self):
        self.history.clear()

    @classmethod
    def _model(cls):
        if cls._llm is None:
            from llama_cpp import Llama

            cls._llm = Llama(model_path=str(MODEL_PATH), n_ctx=4096, n_threads=max(1, (os.cpu_count() or 4)),
                             verbose=False)
        cls._last_used = time.monotonic()
        return cls._llm

    @classmethod
    def unload_if_idle(cls):
        if cls._llm is not None and time.monotonic() - cls._last_used > IDLE_UNLOAD_SECONDS:
            if cls._lock.acquire(blocking=False):  # never wait on an answer in progress
                try:
                    cls._llm = None
                finally:
                    cls._lock.release()

    def ask(self, text: str, facts: list[str], on_token, stop=lambda: False) -> str:
        """Answers `text`; `facts` are the built-in check results (in English)."""
        language = i18n.ENGLISH_NAMES.get(i18n.current(), "English")
        content = text
        if facts:
            content += "\n\n[Sentinel built-in check results]\n" + "\n".join(f"- {f}" for f in facts)
        messages = [{"role": "system", "content": SYSTEM_PROMPT.format(language=language)}]
        messages += self.history[-2 * MAX_TURNS:]
        messages.append({"role": "user", "content": content + " /no_think"})
        answer = []
        with self._lock:
            llm = self._model()
            for chunk in llm.create_chat_completion(messages, max_tokens=500, temperature=0.4, stream=True):
                if stop():
                    break
                token = chunk["choices"][0]["delta"].get("content")
                if not token:
                    continue
                answer.append(token)
                shown = "".join(answer)
                if "<think>" in shown and "</think>" not in shown:
                    continue  # the model's (empty) thinking block
                on_token(_clean(shown))
            Assistant._last_used = time.monotonic()
        reply = _clean("".join(answer))
        self.history += [{"role": "user", "content": content}, {"role": "assistant", "content": reply}]
        return reply


def _clean(text: str) -> str:
    if "</think>" in text:
        text = text.split("</think>", 1)[1]
    return text.lstrip()


def model_size_text() -> str:
    return f"{MODEL_SIZE / 1e9:.1f} GB"


def model_path() -> Path:
    return MODEL_PATH
