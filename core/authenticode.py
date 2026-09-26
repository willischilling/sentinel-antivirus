"""Checks whether a file carries a valid publisher (Authenticode) signature,
using Windows' own verifier (WinVerifyTrust). Handles both signatures embedded
in the file and catalog signatures, which is how most Windows system files
are signed. Revocation checks are skipped so this never waits on the network.
"""
import ctypes
import functools
import msvcrt
import sys
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SignatureInfo:
    signed: bool
    publisher: str | None = None
    kind: str | None = None  # "embedded" or "catalog"


UNSIGNED = SignatureInfo(False)

if sys.platform == "win32":
    wintrust = ctypes.WinDLL("wintrust")
    crypt32 = ctypes.WinDLL("crypt32")

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
        0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class WINTRUST_CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                    ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                    ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                    ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pInfo", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    class CRYPT_PROVIDER_CERT(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]

    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]

    WTD_UI_NONE, WTD_REVOKE_NONE = 2, 0
    WTD_CHOICE_FILE, WTD_CHOICE_CATALOG = 1, 2
    WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE = 1, 2
    WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

    wintrust.WinVerifyTrust.restype = wintypes.LONG
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
    wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    wintrust.WTHelperGetProvCertFromChain.restype = ctypes.POINTER(CRYPT_PROVIDER_CERT)
    wintrust.WTHelperGetProvCertFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD
    crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    wintrust.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
    wintrust.CryptCATAdminAcquireContext2.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p,
                                                      wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
    wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
    wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                                              ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                                                              wintypes.DWORD]
    wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
    wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                                          wintypes.DWORD, ctypes.c_void_p]
    wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
    wintrust.CryptCATCatalogInfoFromContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO),
                                                        wintypes.DWORD]
    wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
    wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]


def _verify(choice, info) -> SignatureInfo | None:
    """Runs WinVerifyTrust; returns the publisher on success, None if not trusted."""
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = choice
    data.pInfo = ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
    action = GUID.from_buffer_copy(WINTRUST_ACTION_GENERIC_VERIFY_V2)
    status = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    try:
        if status != 0:
            return None
        return SignatureInfo(True, _publisher(data.hWVTStateData),
                             "embedded" if choice == WTD_CHOICE_FILE else "catalog")
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))


def _publisher(state) -> str | None:
    prov = wintrust.WTHelperProvDataFromStateData(state)
    signer = wintrust.WTHelperGetProvSignerFromChain(prov, 0, False, 0) if prov else None
    cert = wintrust.WTHelperGetProvCertFromChain(signer, 0) if signer else None
    if not cert or not cert.contents.pCert:
        return None
    buf = ctypes.create_unicode_buffer(256)
    crypt32.CertGetNameStringW(cert.contents.pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, 256)
    return buf.value or None


def _verify_embedded(path: str) -> SignatureInfo | None:
    info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    return _verify(WTD_CHOICE_FILE, info)


def _verify_catalog(path: str) -> SignatureInfo | None:
    with open(path, "rb") as f:
        handle = msvcrt.get_osfhandle(f.fileno())
        for algorithm in ("SHA256", "SHA1"):  # newer catalogs use SHA-256, older ones SHA-1
            admin = wintypes.HANDLE()
            if not wintrust.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, algorithm, None, 0):
                continue
            try:
                size = wintypes.DWORD(0)
                wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, handle, ctypes.byref(size), None, 0)
                digest = (ctypes.c_ubyte * size.value)()
                if not size.value or not wintrust.CryptCATAdminCalcHashFromFileHandle2(
                        admin, handle, ctypes.byref(size), digest, 0):
                    continue
                catalog = wintrust.CryptCATAdminEnumCatalogFromHash(admin, digest, size.value, 0, None)
                if not catalog:
                    continue
                try:
                    cat_info = CATALOG_INFO()
                    cat_info.cbStruct = ctypes.sizeof(CATALOG_INFO)
                    if not wintrust.CryptCATCatalogInfoFromContext(catalog, ctypes.byref(cat_info), 0):
                        continue
                    member_tag = bytes(digest).hex().upper()
                    info = WINTRUST_CATALOG_INFO()
                    info.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
                    info.pcwszCatalogFilePath = cat_info.wszCatalogFile
                    info.pcwszMemberTag = member_tag
                    info.pcwszMemberFilePath = path
                    info.hMemberFile = handle
                    info.pbCalculatedFileHash = ctypes.cast(digest, ctypes.c_void_p)
                    info.cbCalculatedFileHash = size.value
                    info.hCatAdmin = admin
                    result = _verify(WTD_CHOICE_CATALOG, info)
                    if result:
                        return result
                finally:
                    wintrust.CryptCATAdminReleaseCatalogContext(admin, catalog, 0)
            finally:
                wintrust.CryptCATAdminReleaseContext(admin, 0)
    return None


@functools.lru_cache(maxsize=4096)
def _check_cached(path: str, mtime_ns: int, size: int) -> SignatureInfo:
    try:
        return _verify_embedded(path) or _verify_catalog(path) or UNSIGNED
    except OSError:
        return UNSIGNED


def check(path: Path) -> SignatureInfo:
    if sys.platform != "win32":
        return UNSIGNED
    try:
        st = path.stat()
    except OSError:
        return UNSIGNED
    return _check_cached(str(path), st.st_mtime_ns, st.st_size)
