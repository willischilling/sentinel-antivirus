"""The Wi-Fi network this PC is connected to, and whether it has a password,
read with Windows' native Wi-Fi API (wlanapi.dll). Used by auto-VPN.

Newer Windows versions only give apps the network name (SSID) with location
permission; whether the network is open (no password) is available either way,
and that's what auto-VPN mostly needs.
"""
import ctypes
from ctypes import wintypes
from dataclasses import dataclass

WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7
WLAN_INTERFACE_STATE_CONNECTED = 1


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", ctypes.c_uint)]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", wintypes.ULONG), ("ucSSID", ctypes.c_ubyte * 32)]


class WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID), ("dot11BssType", ctypes.c_uint), ("dot11Bssid", ctypes.c_ubyte * 6),
                ("dot11PhyType", ctypes.c_uint), ("uDot11PhyIndex", wintypes.ULONG),
                ("wlanSignalQuality", wintypes.ULONG), ("ulRxRate", wintypes.ULONG), ("ulTxRate", wintypes.ULONG)]


class WLAN_SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("bSecurityEnabled", wintypes.BOOL), ("bOneXEnabled", wintypes.BOOL),
                ("dot11AuthAlgorithm", ctypes.c_uint), ("dot11CipherAlgorithm", ctypes.c_uint)]


class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("isState", ctypes.c_uint), ("wlanConnectionMode", ctypes.c_uint),
                ("strProfileName", ctypes.c_wchar * 256),
                ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
                ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES)]


@dataclass
class WifiConnection:
    name: str          # SSID, or the Windows profile name if the SSID is hidden from apps
    secured: bool      # False = open network (no password)


def current() -> WifiConnection | None:
    """The connected Wi-Fi network, or None (not on Wi-Fi, no Wi-Fi adapter, or no access)."""
    try:
        wlan = ctypes.WinDLL("wlanapi")
    except OSError:
        return None
    handle, version = wintypes.HANDLE(), wintypes.DWORD()
    if wlan.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
        return None
    try:
        interfaces = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(interfaces)) != 0:
            return None
        try:
            count = interfaces.contents.dwNumberOfItems
            items = ctypes.cast(ctypes.byref(interfaces.contents.InterfaceInfo),
                                ctypes.POINTER(WLAN_INTERFACE_INFO * count)).contents
            for info in items:
                if info.isState != WLAN_INTERFACE_STATE_CONNECTED:
                    continue
                size, data = wintypes.DWORD(), ctypes.c_void_p()
                if wlan.WlanQueryInterface(handle, ctypes.byref(info.InterfaceGuid),
                                           WLAN_INTF_OPCODE_CURRENT_CONNECTION, None, ctypes.byref(size),
                                           ctypes.byref(data), None) != 0:
                    continue
                try:
                    conn = ctypes.cast(data, ctypes.POINTER(WLAN_CONNECTION_ATTRIBUTES)).contents
                    ssid = conn.wlanAssociationAttributes.dot11Ssid
                    name = bytes(ssid.ucSSID[:ssid.uSSIDLength]).decode("utf-8", "replace")
                    return WifiConnection(name or conn.strProfileName,
                                          bool(conn.wlanSecurityAttributes.bSecurityEnabled))
                finally:
                    wlan.WlanFreeMemory(data)
        finally:
            wlan.WlanFreeMemory(interfaces)
    finally:
        wlan.WlanCloseHandle(handle, None)
    return None
