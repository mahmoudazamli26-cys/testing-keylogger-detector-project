#!/usr/bin/env python3
"""
Keylogger Detection Tool v2 (Process, API Hook, Script & Persistence Monitor + GUI)
===================================================================================
A lightweight, from-scratch defensive tool that monitors running processes,
inspects PE import tables for keyboard-hooking APIs, scans script files run by
interpreters, verifies Authenticode signatures with WinVerifyTrust, checks persistence locations,
and alerts the user via a dark-themed SOC Tkinter GUI or the CLI.

Primary Target: Windows 10 / 11 (Python 3.9+)
Cross-Platform: Linux /proc fallback for lab testing (PE / registry checks are Windows-only).

Usage:
    python keylogger_detector.py                 # GUI (default)
    python keylogger_detector.py --scan          # one-time CLI scan
    python keylogger_detector.py --scan --interactive
    python keylogger_detector.py --monitor --interval 5
    python keylogger_detector.py --scan --trust-publisher "Some Vendor Ltd"
"""

from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import json
import math
import mmap
import ntpath
import os
import queue
import re
import shlex
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import warnings
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Optional psutil support for richer metrics; falls back to native OS APIs if absent
try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW: no console flashes from the GUI

FLAG_THRESHOLD = 35                  # minimum score to report a process
PERSISTENCE_RESCAN_SECONDS = 120     # how often the monitors re-check persistence
MAX_PE_BYTES = 256 * 1024 * 1024     # PE files are memory-mapped, so this can be generous
MAX_STRING_SCAN_BYTES = 24 * 1024 * 1024  # raw string scans (dynamic APIs / PyInstaller) cost more
MAX_HASH_BYTES = 512 * 1024 * 1024
MAX_SCRIPT_BYTES = 1024 * 1024
BEHAVIOR_WINDOW_SECONDS = 30
MAX_BEHAVIOR_TRACE_BYTES = 4 * 1024 * 1024
FILETIME_UNIX_EPOCH = 116444736000000000

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_NAME = SCRIPT_PATH.name.lower()


# ============================================================================
# Windows locations (derived from the environment, never hard-coded to C:)
# ============================================================================

SYSTEM_ROOT = (os.environ.get("SystemRoot") or r"C:\Windows").lower().rstrip("\\")
SYSTEM32 = SYSTEM_ROOT + "\\system32\\"
SYSWOW64 = SYSTEM_ROOT + "\\syswow64\\"
SYSTEM_DIRS: Tuple[str, ...] = (SYSTEM32, SYSWOW64)
SYSTEMAPPS_PREFIX = SYSTEM_ROOT + "\\systemapps\\"


def _program_files_dirs() -> List[str]:
    dirs: List[str] = []
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        val = os.environ.get(var)
        if val:
            dirs.append(val.lower().rstrip("\\") + "\\")
    dirs = list(dict.fromkeys(dirs))
    return dirs or ["c:\\program files\\", "c:\\program files (x86)\\"]


def _build_trusted_prefixes() -> Tuple[str, ...]:
    prefixes = list(SYSTEM_DIRS)
    for pf in _program_files_dirs():
        # Trailing backslash on every entry: "...\microsoft\" must not match "...\microsoftfake\".
        for sub in ("windows defender\\", "microsoft\\", "microsoft office\\"):
            prefixes.append(pf + sub)
    prog_data = os.environ.get("ProgramData")
    if prog_data:
        prefixes.append(prog_data.lower().rstrip("\\") + "\\microsoft\\windows defender\\")
    return tuple(prefixes)


# Trusted install locations (writable by admins only) used to reduce false positives.
TRUSTED_EXE_PREFIXES: Tuple[str, ...] = _build_trusted_prefixes()

# Core Windows processes and the *exact* directories they are allowed to run from.
PROCESS_EXPECTED_DIRS: Dict[str, Tuple[str, ...]] = {
    "svchost.exe": SYSTEM_DIRS,
    "csrss.exe": (SYSTEM32,),
    "lsass.exe": (SYSTEM32,),
    "wininit.exe": (SYSTEM32,),
    "services.exe": (SYSTEM32,),
    "smss.exe": (SYSTEM32,),
    "taskhostw.exe": (SYSTEM32,),
    "dwm.exe": (SYSTEM32,),
    "conhost.exe": SYSTEM_DIRS,
    "ctfmon.exe": SYSTEM_DIRS,
    "explorer.exe": (SYSTEM_ROOT + "\\", SYSWOW64),
}

# Shell/UI hosts shipped as packaged apps under C:\Windows\SystemApps\<package>\
SYSTEMAPPS_PROCESSES: Set[str] = {
    "searchhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "textinputhost.exe",
}

# Kernel pseudo-processes: they have no executable on disk, so a name alone is only
# trusted when no image path is reported.
KERNEL_PSEUDO_PROCESSES: Set[str] = {
    "system", "system idle process", "registry", "memory compression", "secure system",
}


# ============================================================================
# Detection Signatures & Heuristics
# ============================================================================

# Win32 APIs commonly abused by keyloggers and input-capture malware: name -> (weight, why)
SUSPICIOUS_WIN_APIS: Dict[str, Tuple[int, str]] = {
    "SetWindowsHookExA": (35, "Installs a global/thread hook (e.g. WH_KEYBOARD_LL)"),
    "SetWindowsHookExW": (35, "Installs a global/thread hook (e.g. WH_KEYBOARD_LL)"),
    "GetAsyncKeyState": (30, "Polls real-time hardware key states"),
    "GetKeyboardState": (25, "Reads status of all 256 virtual keys"),
    "GetKeyState": (15, "Queries virtual key state"),
    "RegisterRawInputDevices": (25, "Registers for raw HID/keyboard input"),
    "GetRawInputData": (25, "Reads raw keyboard input buffer"),
    "AttachThreadInput": (20, "Attaches input processing to another thread"),
    "MapVirtualKeyA": (10, "Translates virtual-key codes to characters"),
    "MapVirtualKeyW": (10, "Translates virtual-key codes to characters"),
    "ToUnicode": (10, "Translates key presses to Unicode text"),
    "ToUnicodeEx": (10, "Translates key presses to Unicode text"),
    "ToAscii": (10, "Translates key presses to ASCII text"),
}

# A binary only counts as a capture candidate if it has a real *capability*;
# weak helper APIs alone (GetKeyState, MapVirtualKey...) are used by almost every GUI app.
HOOK_APIS = {"SetWindowsHookExA", "SetWindowsHookExW"}
POLL_APIS = {"GetAsyncKeyState", "GetKeyboardState"}
RAW_APIS = {"RegisterRawInputDevices", "GetRawInputData"}
TRANSLATE_APIS = {"MapVirtualKeyA", "MapVirtualKeyW", "ToUnicode", "ToUnicodeEx", "ToAscii"}
LOADER_APIS = {"GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"}

# (pattern, points, description, interpreter_only)
# interpreter_only patterns are weak words that only mean something when a script host runs them
# (otherwise an editor opening "keylog.txt" or a folder called "keyboard" would be flagged).
SUSPICIOUS_CMD_PATTERNS: List[Tuple[str, int, str, bool]] = [
    (r"pynput", 40, "Uses Python 'pynput' keyboard/mouse listener", True),
    (r"\bkeyboard\b", 30, "References 'keyboard' hooking module", True),
    (r"pyHook|pyWinhook", 40, "Uses legacy Windows hooking library", True),
    (r"GetAsyncKeyState|SetWindowsHookEx", 45, "Inline Win32 keylogging API in command", False),
    (r"WH_KEYBOARD_LL|WH_KEYBOARD\b", 45, "Low-level keyboard hook constant in command", False),
    (r"-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", 30, "Obfuscated/Encoded PowerShell command", True),
    (r"keylog|keystroke|stealer", 35, "Suspicious keyword in command line", True),
]

# Path fragments are matched against lowercase text; both "\" and "/" separators are handled.
SUSPICIOUS_PATH_FRAGMENTS: List[Tuple[str, int, str]] = [
    (r"\\appdata\\local\\temp\\", 25, "Running from user Temp directory"),
    (r"\\windows\\temp\\", 30, "Running from Windows Temp directory"),
    (r"\\users\\public\\", 25, "Running from Public user folder"),
    (r"\\downloads\\", 15, "Running directly from Downloads folder"),
    (r"\\\$recycle\.bin\\", 40, "Running from Recycle Bin"),
    (r"/tmp/|/dev/shm/", 30, "Running from temporary/shared memory directory"),
]

# Bare "logger"/"klog" were dropped: they match "eventlogger", "backlog", etc.
SUSPICIOUS_NAME_KEYWORDS: List[str] = ["keylog", "keystroke", "spyware", "stealer"]

# Content patterns for script files run by interpreters (python x.py, powershell -File x.ps1 ...)
SCRIPT_CONTENT_PATTERNS: List[Tuple[str, int, str]] = [
    (r"^\s*(?:from|import)\s+pynput\b", 50, "Script imports 'pynput' (keyboard listener)"),
    (r"^\s*(?:from|import)\s+(?:pyHook|pyWinhook)\b", 40, "Script imports a Windows hooking library"),
    (r"^\s*(?:from|import)\s+keyboard\b|\bkeyboard\.(?:on_press|on_release|hook|record|read_key|read_event)\b",
     30, "Script uses the 'keyboard' capture module"),
    (r"GetAsyncKeyState|GetKeyboardState|SetWindowsHookEx", 45, "Script calls Win32 key-capture APIs"),
    (r"WH_KEYBOARD_LL|WH_KEYBOARD\b", 45, "Script uses a low-level keyboard hook constant"),
    (r"Add-Type[\s\S]{0,400}user32", 30, "PowerShell P/Invoke of user32 (possible input capture)"),
]
EXFIL_PATTERN = (
    r"smtplib|ftplib|requests\.post|urlopen|discord(?:app)?\.com/api/webhooks|api\.telegram\.org"
    r"|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|sendmail"
)

SCRIPT_EXTENSIONS = (".py", ".pyw", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
                     ".bat", ".cmd", ".ahk", ".sh", ".pl", ".rb")

# Python / script hosts. Their *command line* (and script file) matters more than their binary.
_PY_RE = re.compile(r"^(?:pythonw?|pyw?)(?:\d+(?:\.\d+)*)?(?:\.exe)?$")
INTERPRETER_NAMES: Set[str] = {
    "powershell.exe", "powershell", "pwsh.exe", "pwsh", "wscript.exe", "cscript.exe", "mshta.exe",
    "node.exe", "node", "bash", "sh", "perl", "perl.exe", "ruby", "ruby.exe",
}
WINDOWLESS_HOSTS: Set[str] = {"pythonw.exe", "wscript.exe", "cscript.exe"}
SCRIPT_HOST_RE = re.compile(
    r"\b(?:pythonw?|py|powershell|pwsh|wscript|cscript|mshta|node|autohotkey\w*)(?:\.exe)?\b", re.IGNORECASE
)

# Exact certificate CN/O values (lowercase) whose *valid* signature downgrades API-import findings.
# This is a starter list: extend it with --trust-publisher "Exact Publisher Name".
TRUSTED_PUBLISHERS: Set[str] = {
    "microsoft corporation", "microsoft windows", "google llc", "mozilla corporation",
    "nvidia corporation", "intel corporation", "adobe inc.", "jetbrains s.r.o.",
    "zoom video communications, inc.", "dropbox, inc.", "slack technologies, llc",
}

# Pre-compiled regexes
_CMD_RE = [(re.compile(p, re.IGNORECASE), pts, desc, interp) for p, pts, desc, interp in SUSPICIOUS_CMD_PATTERNS]
_PATH_RE = [(re.compile(p), pts, desc) for p, pts, desc in SUSPICIOUS_PATH_FRAGMENTS]
_SCRIPT_RE = [(re.compile(p, re.IGNORECASE | re.MULTILINE), pts, desc) for p, pts, desc in SCRIPT_CONTENT_PATTERNS]
_EXFIL_RE = re.compile(EXFIL_PATTERN, re.IGNORECASE)
_DN_RE = re.compile(r'(?:^|,\s*)(CN|O)=("(?:[^"]|"")*"|[^,]*)')


# ============================================================================
# Native Windows Authenticode Verification (WinVerifyTrust via ctypes)
# ============================================================================

# WinVerifyTrust constants
_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_REVOCATION_CHECK_NONE = 0x00000010
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000
_WTD_UICONTEXT_EXECUTE = 0

# CertGetNameStringW constants
_CERT_NAME_RDN_TYPE = 2
_CERT_X500_NAME_STR = 3
_CERT_NAME_STR_REVERSE_FLAG = 0x02000000

# WinVerifyTrust HRESULT status codes (unsigned 32-bit)
_ERROR_SUCCESS = 0x00000000
_TRUST_E_NOSIGNATURE = 0x800B0100
_TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
_TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
_TRUST_E_BAD_DIGEST = 0x80096010
_CRYPT_E_HASH_VALUE = 0x80091007
_TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
_TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
_CERT_E_EXPIRED = 0x800B0101
_CERT_E_UNTRUSTEDROOT = 0x800B0109
_CERT_E_REVOKED = 0x800B010C
_CERT_E_CHAINING = 0x800B010A

_NOT_SIGNED_CODES = {
    _TRUST_E_NOSIGNATURE,
    _TRUST_E_SUBJECT_FORM_UNKNOWN,
    _TRUST_E_PROVIDER_UNKNOWN,
}
_HASH_MISMATCH_CODES = {
    _TRUST_E_BAD_DIGEST,
    _CRYPT_E_HASH_VALUE,
}
_NOT_TRUSTED_CODES = {
    _TRUST_E_EXPLICIT_DISTRUST,
    _TRUST_E_SUBJECT_NOT_TRUSTED,
    _CERT_E_EXPIRED,
    _CERT_E_UNTRUSTEDROOT,
    _CERT_E_REVOKED,
    _CERT_E_CHAINING,
}


def _map_wintrust_status(hr: int) -> str:
    """Map a WinVerifyTrust LONG return code to an Authenticode status string."""
    code = hr & 0xFFFFFFFF
    if code == _ERROR_SUCCESS:
        return "Valid"
    if code in _NOT_SIGNED_CODES:
        return "NotSigned"
    if code in _HASH_MISMATCH_CODES:
        return "HashMismatch"
    if code in _NOT_TRUSTED_CODES:
        return "NotTrusted"
    return "UnknownError"


_WINTRUST_API = None
_WINTRUST_INIT_LOCK = threading.Lock()


def _init_wintrust_api():
    """Lazily bind wintrust.dll and crypt32.dll functions on Windows (thread-safe)."""
    global _WINTRUST_API
    if _WINTRUST_API is not None:
        return _WINTRUST_API
    if not IS_WINDOWS:
        return None

    with _WINTRUST_INIT_LOCK:
        if _WINTRUST_API is not None:
            return _WINTRUST_API
        try:
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            class WINTRUST_FILE_INFO(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p),
                ]

            class WINTRUST_DATA(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p),
                ]

            class CRYPT_PROVIDER_CERT(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", wintypes.DWORD),
                    ("pCert", ctypes.c_void_p),
                ]

            wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
            crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)

            wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
            wintrust.WinVerifyTrust.restype = wintypes.LONG

            wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
            wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p

            wintrust.WTHelperGetProvSignerFromChain.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
            ]
            wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p

            wintrust.WTHelperGetProvCertFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            wintrust.WTHelperGetProvCertFromChain.restype = ctypes.POINTER(CRYPT_PROVIDER_CERT)

            crypt32.CertGetNameStringW.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD,
            ]
            crypt32.CertGetNameStringW.restype = wintypes.DWORD

            # WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
            action_guid = GUID(
                0x00AAC56B,
                0xCD44,
                0x11D0,
                (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
            )

            _WINTRUST_API = {
                "wintypes": wintypes,
                "WINTRUST_FILE_INFO": WINTRUST_FILE_INFO,
                "WINTRUST_DATA": WINTRUST_DATA,
                "wintrust": wintrust,
                "crypt32": crypt32,
                "action_guid": action_guid,
            }
        except Exception:
            _WINTRUST_API = False
        return _WINTRUST_API


def _winverifytrust_file(exe_path: str) -> Tuple[str, str]:
    """
    Verify Authenticode signature directly via WinVerifyTrust (wintrust.dll) and extract
    the signer's X.500 subject via crypt32.dll.
    """
    api = _init_wintrust_api()
    if not api:
        return "Unknown", ""

    wintypes = api["wintypes"]
    wintrust = api["wintrust"]
    crypt32 = api["crypt32"]
    action_guid = api["action_guid"]

    file_info = api["WINTRUST_FILE_INFO"]()
    file_info.cbStruct = ctypes.sizeof(file_info)
    file_info.pcwszFilePath = exe_path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    wtd = api["WINTRUST_DATA"]()
    wtd.cbStruct = ctypes.sizeof(wtd)
    wtd.pPolicyCallbackData = None
    wtd.pSIPClientData = None
    wtd.dwUIChoice = _WTD_UI_NONE
    wtd.fdwRevocationChecks = _WTD_REVOKE_NONE
    wtd.dwUnionChoice = _WTD_CHOICE_FILE
    wtd.pFile = ctypes.pointer(file_info)
    wtd.dwStateAction = _WTD_STATEACTION_VERIFY
    wtd.hWVTStateData = None
    wtd.pwszURLReference = None
    # Offline/cache-only verification avoids network stalls on CRL/OCSP checks.
    wtd.dwProvFlags = _WTD_REVOCATION_CHECK_NONE | _WTD_CACHE_ONLY_URL_RETRIEVAL
    wtd.dwUIContext = _WTD_UICONTEXT_EXECUTE
    wtd.pSignatureSettings = None

    subject = ""
    try:
        hr = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
        status = _map_wintrust_status(hr)

        if wtd.hWVTStateData and status in {"Valid", "NotTrusted", "HashMismatch"}:
            p_prov_data = wintrust.WTHelperProvDataFromStateData(wtd.hWVTStateData)
            if p_prov_data:
                p_signer = wintrust.WTHelperGetProvSignerFromChain(p_prov_data, 0, False, 0)
                if p_signer:
                    p_prov_cert = wintrust.WTHelperGetProvCertFromChain(p_signer, 0)
                    if p_prov_cert and p_prov_cert.contents.pCert:
                        p_cert = p_prov_cert.contents.pCert
                        str_type = wintypes.DWORD(_CERT_X500_NAME_STR | _CERT_NAME_STR_REVERSE_FLAG)
                        cch = crypt32.CertGetNameStringW(
                            p_cert, _CERT_NAME_RDN_TYPE, 0, ctypes.byref(str_type), None, 0
                        )
                        if cch > 1:
                            buf = ctypes.create_unicode_buffer(cch)
                            written = crypt32.CertGetNameStringW(
                                p_cert, _CERT_NAME_RDN_TYPE, 0, ctypes.byref(str_type), buf, cch
                            )
                            if written > 1:
                                subject = buf.value
        return status, subject
    except Exception:
        return "Unknown", ""
    finally:
        if wtd.hWVTStateData:
            wtd.dwStateAction = _WTD_STATEACTION_CLOSE
            try:
                wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
            except Exception:
                pass


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class ProcessFinding:
    pid: int
    name: str
    exe_path: str
    cmdline: str
    score: int
    severity: str
    reasons: List[str] = field(default_factory=list)
    matched_apis: List[str] = field(default_factory=list)
    has_network: bool = False
    start: int = 0           # process start time; (pid, start) identifies a process even if PIDs are reused
    wl_key: str = ""         # whitelist key (SHA-256 based) or "" if the image could not be hashed
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds"))

    script_path: str = ""

    @property
    def file_path(self) -> str:
        return self.script_path or self.exe_path

    @property
    def file_name(self) -> str:
        return ntpath.basename(self.file_path)


@dataclass
class PersistenceFinding:
    location: str
    name: str
    command: str
    reason: str


@dataclass
class PEInfo:
    apis: List[str] = field(default_factory=list)          # suspicious APIs in the import table
    dynamic_apis: List[str] = field(default_factory=list)  # API names present as strings + GetProcAddress imported
    packed: bool = False                                   # high entropy and almost no imports
    bundled_libs: List[str] = field(default_factory=list)  # keylogging libs inside a PyInstaller bundle


def proc_key(pid: int, start: int) -> str:
    return f"{pid}-{int(start)}"


# ============================================================================
# Small helpers
# ============================================================================

def default_data_dir() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("APPDATA") or Path.home()) / "KeyloggerDetector"
    return Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "keylogger_detector"


def configure_protected_storage() -> Path:
    """Set up administrator-writable logs and whitelist storage on Windows."""
    if not IS_WINDOWS or not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError("Protected storage requires an elevated Windows session.")

    data_dir = Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "KeyloggerDetector"
    if data_dir.resolve() != data_dir.absolute():
        raise OSError(f"Protected storage cannot use a redirected directory: {data_dir}")
    data_dir.mkdir(parents=True, exist_ok=True)
    # Use well-known SIDs so the ACL also works on localized Windows.
    subprocess.run(
        ["icacls", str(data_dir), "/grant:r", "*S-1-5-18:(OI)(CI)F",
         "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/inheritance:r"],
        check=True, capture_output=True, text=True, creationflags=NO_WINDOW,
    )
    (data_dir / "Logs").mkdir(exist_ok=True)
    return data_dir


SIGN_IN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
SIGN_IN_VALUE = "KeyloggerDetector"


def sign_in_command() -> str:
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    log = default_data_dir() / "keylogger_alerts.jsonl"
    return subprocess.list2cmdline([str(pythonw), str(SCRIPT_PATH), "--monitor", "--log", str(log)])


def configure_sign_in(enable: bool) -> None:
    if not IS_WINDOWS:
        raise OSError("Start at sign-in is available on Windows.")
    import winreg

    if enable:
        if not Path(sys.executable).with_name("pythonw.exe").is_file():
            raise OSError("pythonw.exe is required for background monitoring at sign-in.")
        command = sign_in_command()
        if len(command) > 260:
            raise OSError("The startup command is too long. Move the detector to a shorter path.")
        default_data_dir().mkdir(parents=True, exist_ok=True)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, SIGN_IN_KEY) as key:
            winreg.SetValueEx(key, SIGN_IN_VALUE, 0, winreg.REG_SZ, command)
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SIGN_IN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, SIGN_IN_VALUE)
        except FileNotFoundError:
            pass


def _stamp(path: str) -> Optional[Tuple[int, int]]:
    """(size, mtime) used as a cache key so caches invalidate when a file changes."""
    try:
        st = os.stat(path)
        return st.st_size, int(st.st_mtime)
    except OSError:
        return None


def exe_dir(exe_lower: str) -> str:
    """Exact parent directory of a Windows path, lowercase, with trailing backslash."""
    return ntpath.dirname(exe_lower.replace("/", "\\")).rstrip("\\") + "\\"


def is_interpreter(name_lower: str) -> bool:
    return bool(_PY_RE.match(name_lower)) or name_lower in INTERPRETER_NAMES or name_lower.startswith("autohotkey")


def path_hit(text: str) -> Optional[Tuple[int, str]]:
    low = text.lower()
    variants = (low, low.replace("/", "\\"))
    best: Optional[Tuple[int, str]] = None
    for rx, pts, desc in _PATH_RE:
        if any(rx.search(v) for v in variants) and (best is None or pts > best[0]):
            best = (pts, desc)
    return best


def shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in Counter(buf).values())


def run_powershell(script: str, timeout: int = 20, env: Optional[Dict[str, str]] = None) -> str:
    """Run a PowerShell snippet with UTF-8 output and no console window. Returns '' on any failure."""
    if not IS_WINDOWS:
        return ""
    wrapped = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + script
    try:
        return subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", wrapped],
            text=True, encoding="utf-8", errors="ignore", stderr=subprocess.DEVNULL,
            timeout=timeout, env=env, creationflags=NO_WINDOW,
        )
    except (subprocess.SubprocessError, OSError):
        return ""


def parse_json_list(text: str) -> List[dict]:
    """PowerShell's ConvertTo-Json yields '', one object, or a list. Normalise to a list of dicts."""
    if not text or not text.strip():
        return []
    try:
        raw = json.loads(text)
    except ValueError:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    return [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []


def publisher_names(subject: str) -> Set[str]:
    names: Set[str] = set()
    for _, val in _DN_RE.findall(subject or ""):
        val = val.strip()
        if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = val[1:-1].replace('""', '"')
        if val:
            names.add(val.lower())
    return names


def publisher_display(subject: str) -> str:
    for kind, val in _DN_RE.findall(subject or ""):
        if kind == "CN":
            return val.strip().strip('"')
    return subject or "unknown"


# ============================================================================
# Whitelist (SHA-256 based, stored in a per-user directory)
# ============================================================================

_WL_KEY_RE = re.compile(r"^[0-9a-f]{64}(?::[0-9a-f]{64})?$")


class Whitelist:
    """
    Whitelist keyed by the SHA-256 of the executable (not by name or path, which are trivial to fake).
    For script hosts (python, powershell...) the key also includes a hash of the command line, so
    whitelisting python.exe for one script never blinds the tool to other scripts.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: Dict[str, Dict[str, str]] = {}
        self.ignored_legacy = 0
        self._hashes: Dict[Tuple[str, int, int], str] = {}
        self._lock = threading.RLock()
        self.load()

    def load(self) -> None:
        with self._lock:
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                raw = {}
            except (OSError, ValueError):
                return
            self.ignored_legacy = 0
            if isinstance(raw, dict):
                self.entries = {
                    k: (v if isinstance(v, dict) else {})
                    for k, v in raw.items() if isinstance(k, str) and _WL_KEY_RE.match(k)
                }
            elif isinstance(raw, list):
                # Old v1 format (names / paths). Those entries were spoofable, so they are not imported.
                self.entries = {}
                self.ignored_legacy = len(raw)

    def _file_hash(self, path: str) -> Optional[str]:
        st = _stamp(path)
        if st is None or st[0] > MAX_HASH_BYTES:
            return None
        ck = (path.lower(), st[0], st[1])
        with self._lock:
            cached = self._hashes.get(ck)
        if cached:
            return cached
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(chunk)
        except OSError:
            return None
        hex_digest = digest.hexdigest()
        with self._lock:
            self._hashes[ck] = hex_digest
        return hex_digest

    def key_for(self, proc: Dict) -> Optional[str]:
        exe = proc.get("exe") or ""
        if not exe:
            return None
        digest = self._file_hash(exe)
        if not digest:
            return None
        if is_interpreter((proc.get("name") or "").lower()):
            cmd_norm = " ".join((proc.get("cmdline") or "").lower().split())
            return digest + ":" + hashlib.sha256(cmd_norm.encode("utf-8", "ignore")).hexdigest()
        return digest

    def has(self, key: str) -> bool:
        with self._lock:
            return key in self.entries

    def add(self, key: str, name: str, path: str) -> bool:
        with self._lock:
            previous = self.entries.get(key)
            self.entries[key] = {
                "name": name, "path": path,
                "added": datetime.datetime.now().isoformat(timespec="seconds"),
            }
            if self._save():
                return True
            if previous is None:
                self.entries.pop(key)
            else:
                self.entries[key] = previous
            return False

    def remove(self, key: str) -> bool:
        with self._lock:
            previous = self.entries.pop(key, None)
            if previous is None:
                return True
            if self._save():
                return True
            self.entries[key] = previous
            return False

    def _save(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(self.entries, indent=2, ensure_ascii=False), encoding="utf-8")
            if not IS_WINDOWS:
                try:
                    os.chmod(tmp, 0o600)
                except OSError:
                    pass
            os.replace(tmp, self.path)  # atomic: never leaves a half-written whitelist
            return True
        except OSError:
            return False


@dataclass
class ScanContext:
    """Caches and options shared across scans (and across threads; dict operations are atomic)."""
    pe_cache: Dict = field(default_factory=dict)
    sig_cache: Dict = field(default_factory=dict)
    script_cache: Dict = field(default_factory=dict)
    whitelist: Optional[Whitelist] = None
    check_signatures: bool = True
    self_pids: Set[int] = field(default_factory=set)
    behavior_trace: Optional[Path] = None
    behavior_findings: Dict[Tuple[int, int], Tuple[int, List[str]]] = field(default_factory=dict)


# ============================================================================
# Pure-Python PE Parser (imports, dynamic-API strings, packing, PyInstaller)
# ============================================================================

def scan_pe(exe_path: str) -> PEInfo:
    """Memory-maps the file (no full read into RAM) and extracts keylogging-relevant indicators."""
    try:
        size = os.path.getsize(exe_path)
        if size < 256 or size > MAX_PE_BYTES:
            return PEInfo()
        with open(exe_path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return _parse_pe(data)
    except (OSError, ValueError, struct.error, IndexError):
        return PEInfo()


def _parse_pe(data) -> PEInfo:
    info = PEInfo()
    n = len(data)
    if data[:2] != b"MZ":
        return info

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > n or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return info

    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == 0x10B:      # PE32
        is64, import_dir = False, opt_off + 104
    elif magic == 0x20B:    # PE32+
        is64, import_dir = True, opt_off + 120
    else:
        return info

    import_rva = struct.unpack_from("<I", data, import_dir)[0]

    sections: List[Tuple[int, int, int, int]] = []  # (rva, mapped size, raw pointer, raw size)
    sec_base = opt_off + opt_size
    for i in range(min(num_sections, 96)):
        sec_off = sec_base + i * 40
        if sec_off + 40 > n:
            break
        v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sec_off + 8)
        sections.append((v_addr, max(v_size, raw_size), raw_ptr, raw_size))

    def rva_to_offset(rva: int) -> Optional[int]:
        for v_addr, size, raw_ptr, _ in sections:
            if v_addr <= rva < v_addr + size:
                off = raw_ptr + (rva - v_addr)
                return off if off < n else None
        return None

    static: Set[str] = set()
    uses_loader = False
    total_imports = 0

    imp_off = rva_to_offset(import_rva) if import_rva else None
    if imp_off is not None:
        step, fmt, ordinal_flag = (8, "<Q", 1 << 63) if is64 else (4, "<I", 1 << 31)
        for idx in range(256):
            desc_off = imp_off + idx * 20
            if desc_off + 20 > n:
                break
            ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", data, desc_off)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            pos = rva_to_offset(ilt_rva or iat_rva)
            if pos is None:
                continue
            for _ in range(2048):
                if pos + step > n:
                    break
                val = struct.unpack_from(fmt, data, pos)[0]
                if val == 0:
                    break
                pos += step
                total_imports += 1
                if val & ordinal_flag:
                    continue
                hint_off = rva_to_offset(val & 0x7FFFFFFF)
                if hint_off is None or hint_off + 2 >= n:
                    continue
                end = data.find(b"\x00", hint_off + 2, hint_off + 2 + 128)
                if end == -1:
                    continue
                fn = data[hint_off + 2:end].decode("ascii", errors="ignore")
                if fn in SUSPICIOUS_WIN_APIS:
                    static.add(fn)
                elif fn in LOADER_APIS:
                    uses_loader = True

    info.apis = sorted(static)

    # APIs resolved at runtime (GetProcAddress) never show up in the import table,
    # but their names are still present as strings inside the binary.
    if uses_loader and n <= MAX_STRING_SCAN_BYTES:
        info.dynamic_apis = sorted(
            api for api in SUSPICIOUS_WIN_APIS if api not in static and data.find(api.encode("ascii")) != -1
        )

    # Packing heuristic: almost no imports + a high-entropy section.
    if total_imports < 15 and sections:
        _, _, raw_ptr, raw_size = max(sections, key=lambda s: s[3])
        if raw_size >= 4096 and raw_ptr < n:
            sample = bytes(data[raw_ptr:min(n, raw_ptr + min(raw_size, 65536))])
            info.packed = shannon_entropy(sample) > 7.2

    # PyInstaller bundles hide the Python code from the import table; look for library names in the archive.
    if n <= MAX_STRING_SCAN_BYTES and b"MEI\x0c\x0b\x0a\x0b\x0e" in data[max(0, n - 65536):]:
        info.bundled_libs = [lib for lib in ("pynput", "pyHook", "pyWinhook") if data.find(lib.encode()) != -1]

    return info


def score_api_imports(apis: List[str]) -> Tuple[int, str]:
    """Score API usage by capability instead of by raw API count."""
    s = set(apis)
    has_hook = bool(s & HOOK_APIS)
    has_poll = bool(s & POLL_APIS)
    has_raw = RAW_APIS <= s
    if not (has_hook or has_poll or has_raw):
        return 0, ""
    total = min(60, sum(SUSPICIOUS_WIN_APIS[a][0] for a in s))
    if has_poll and not (has_hook or has_raw) and not (s & TRANSLATE_APIS):
        return total // 2, " (polling only: common in games/macro tools)"
    return total, ""


def verify_signature(exe_path: str, ctx: ScanContext) -> Tuple[str, str]:
    """Cache native Authenticode results, with PowerShell for unresolved signatures."""
    if not (IS_WINDOWS and ctx.check_signatures):
        return "Unknown", ""
    st = _stamp(exe_path)
    if st is None:
        return "Unknown", ""
    key = (exe_path.lower(), st[0], st[1])
    if key in ctx.sig_cache:
        return ctx.sig_cache[key]

    result = _winverifytrust_file(exe_path)
    # PowerShell can resolve catalog signatures and unsupported trust providers.
    if result[0] in {"NotTrusted", "HashMismatch"} or (result[0] == "Valid" and result[1]):
        ctx.sig_cache[key] = result
        return result

    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath $env:KLD_PATH -ErrorAction SilentlyContinue; "
        "if ($s) { [pscustomobject]@{Status=[string]$s.Status; "
        "Subject=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress }"
    )
    env = dict(os.environ)
    env["KLD_PATH"] = exe_path  # passed via env var so odd characters in the path can't break the command
    rows = parse_json_list(run_powershell(script, timeout=20, env=env))
    if rows:
        result = (str(rows[0].get("Status") or "Unknown"), str(rows[0].get("Subject") or ""))
    ctx.sig_cache[key] = result
    return result


# ============================================================================
# Script file inspection (python x.py / powershell -File x.ps1 ...)
# ============================================================================

def extract_script_path(cmdline: str, argv: Optional[List[str]] = None) -> Optional[str]:
    if argv is None:
        try:
            tokens = [token.strip("\"'") for token in shlex.split(cmdline, posix=not IS_WINDOWS)]
        except ValueError:
            tokens = cmdline.split()
    else:
        tokens = argv
    for token in tokens[1:]:
        if token.lower().endswith(SCRIPT_EXTENSIONS) and os.path.isfile(token):
            return token
    return None


_PYTHON_CAPTURE_MODULES = {"pynput", "pyhook", "pywinhook", "keyboard"}
_PYTHON_CAPTURE_APIS = frozenset(name.lower() for name in (POLL_APIS | HOOK_APIS)) | {
    "setwindowshookex",
}


def _static_xor_characters(node: ast.AST) -> Optional[str]:
    """Recognize an empty-string join of chr(item ^ constant) over byte literals."""
    if not isinstance(node, ast.GeneratorExp) or len(node.generators) != 1:
        return None
    loop = node.generators[0]
    if loop.ifs or loop.is_async or not isinstance(loop.target, ast.Name):
        return None
    call = node.elt
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id == "chr" and len(call.args) == 1 and not call.keywords):
        return None
    expr = call.args[0]
    if not isinstance(expr, ast.BinOp) or not isinstance(expr.op, ast.BitXor):
        return None
    variable, key = expr.left, expr.right
    if isinstance(key, ast.Name):
        variable, key = key, variable
    if not (isinstance(variable, ast.Name) and variable.id == loop.target.id
            and isinstance(key, ast.Constant) and type(key.value) is int
            and 0 <= key.value <= 255):
        return None
    values = loop.iter
    if isinstance(values, ast.Constant) and isinstance(values.value, bytes):
        data = values.value
    elif isinstance(values, (ast.List, ast.Tuple)) and len(values.elts) <= 256:
        if not all(isinstance(item, ast.Constant) and type(item.value) is int
                   and 0 <= item.value <= 255 for item in values.elts):
            return None
        data = [item.value for item in values.elts]
    else:
        return None
    if len(data) > 256:
        return None
    return "".join(chr(byte ^ key.value) for byte in data)


def _static_python_string(node: ast.AST, depth: int = 0) -> Optional[str]:
    if depth >= 12:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if len(node.value) <= 256 else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_python_string(node.left, depth + 1)
        right = _static_python_string(node.right, depth + 1)
        if left is not None and right is not None and len(left) + len(right) <= 256:
            return left + right
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join" and len(node.args) == 1 and not node.keywords
            and isinstance(node.func.value, ast.Constant) and node.func.value.value == ""):
        parts = node.args[0]
        if isinstance(parts, ast.GeneratorExp):
            return _static_xor_characters(parts)
        if isinstance(parts, (ast.List, ast.Tuple)) and len(parts.elts) <= 256:
            fragments = [_static_python_string(part, depth + 1) for part in parts.elts]
            if all(fragment is not None for fragment in fragments):
                joined = "".join(fragments)
                return joined if len(joined) <= 256 else None
    return None


def scan_python_dynamic_names(source: str) -> Tuple[int, List[str]]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return 0, []
    modules, apis, xor_names = set(), set(), set()

    def inspect_call(node: ast.AST, bindings: Dict[str, ast.AST]) -> None:
        if not isinstance(node, ast.Call) or not node.args:
            return
        func = node.func
        is_import = (
            (isinstance(func, ast.Name) and func.id == "__import__")
            or (isinstance(func, ast.Attribute) and func.attr == "import_module"
                and isinstance(func.value, ast.Name) and func.value.id == "importlib")
        )
        if is_import:
            argument = node.args[0]
        elif isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2:
            argument = node.args[1]
        else:
            return
        if isinstance(argument, ast.Name):
            argument = bindings.get(argument.id, argument)
        value = _static_python_string(argument)
        if not value:
            return
        if is_import and value.split(".", 1)[0] in _PYTHON_CAPTURE_MODULES:
            modules.add(value)
        elif not is_import and value.lower() in _PYTHON_CAPTURE_APIS:
            apis.add(value)
        else:
            return
        if any(isinstance(part, ast.BitXor) for part in ast.walk(argument)):
            xor_names.add(value)

    for node in ast.walk(tree):
        inspect_call(node, {})

    # Track simple assignments in straight-line statement blocks. An unknown
    # statement ends the chain so bindings cannot leak across branches or scopes.
    for block in ast.walk(tree):
        body = getattr(block, "body", None)
        if not isinstance(body, list):
            continue
        bindings: Dict[str, ast.AST] = {}
        for statement in body:
            if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                    and isinstance(statement.targets[0], ast.Name)):
                inspect_call(statement.value, bindings)
                bindings[statement.targets[0].id] = statement.value
                continue
            if isinstance(statement, ast.Expr):
                inspect_call(statement.value, bindings)
            elif isinstance(statement, ast.Return):
                inspect_call(statement.value, bindings)
            bindings.clear()

    score, reasons = 0, []
    if modules:
        score += 40
        reasons.append("Dynamic import names a keyboard-capture module: " + ", ".join(sorted(modules)))
    if apis:
        score += 40
        reasons.append("Dynamic attribute lookup names a keyboard-capture API: " + ", ".join(sorted(apis)))
    if xor_names:
        reasons.append("Recovered possible keylogger indicators from XOR: " + ", ".join(sorted(xor_names)))
    return score, reasons


def scan_script_file(path: str, ctx: ScanContext) -> Tuple[int, List[str]]:
    try:
        if Path(path).resolve() == SCRIPT_PATH:
            return 0, []  # never flag this tool's own source file
    except OSError:
        return 0, []
    st = _stamp(path)
    if st is None:
        return 0, []
    key = (path.lower(), st[0], st[1])
    if key in ctx.script_cache:
        return ctx.script_cache[key]

    result: Tuple[int, List[str]] = (0, [])
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_SCRIPT_BYTES)
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = raw.decode("utf-16", errors="ignore")
        else:
            text = raw.decode("utf-8", errors="ignore")
        score, reasons = 0, []
        for rx, pts, desc in _SCRIPT_RE:
            if rx.search(text):
                score += pts
                reasons.append(desc)
        if Path(path).suffix.lower() in (".py", ".pyw"):
            dynamic_score, dynamic_reasons = scan_python_dynamic_names(text)
            score += dynamic_score
            reasons.extend(dynamic_reasons)
        if score and _EXFIL_RE.search(text):
            score += 15
            reasons.append("Script also contains exfiltration code (SMTP/HTTP/webhook)")
        result = (min(60, score), reasons)
    except OSError:
        pass
    ctx.script_cache[key] = result
    return result


# ============================================================================
# Process Enumeration (psutil + Native Fallback)
# ============================================================================

def get_net_pids() -> Optional[Set[int]]:
    """PIDs with an established, non-loopback connection, fetched ONCE per scan. None = unavailable."""
    if HAS_PSUTIL:
        try:
            pids: Set[int] = set()
            for c in psutil.net_connections(kind="inet"):
                if c.status != psutil.CONN_ESTABLISHED or not c.raddr or c.pid is None:
                    continue
                ip = c.raddr.ip
                if ip.startswith("127.") or ip == "::1":
                    continue
                pids.add(c.pid)
            return pids
        except (psutil.AccessDenied, OSError, AttributeError):
            return None
    if IS_WINDOWS:
        out = run_powershell(
            "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
            "Where-Object { $_.RemoteAddress -notin '127.0.0.1','::1' } | "
            "Select-Object -ExpandProperty OwningProcess -Unique | ConvertTo-Json -Compress",
            timeout=15,
        )
        try:
            raw = json.loads(out) if out.strip() else []
        except ValueError:
            return None
        if isinstance(raw, int):
            raw = [raw]
        return {int(x) for x in raw if isinstance(x, int)}
    return None


def _proc_has_net(p) -> bool:
    """Per-process fallback for when the global connection listing is denied (e.g. non-root Linux)."""
    try:
        getter = getattr(p, "net_connections", None) or p.connections
        return any(
            c.status == "ESTABLISHED" and c.raddr and not c.raddr.ip.startswith("127.") and c.raddr.ip != "::1"
            for c in getter(kind="inet")
        )
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return False


def get_processes_snapshot() -> List[Dict]:
    """Return dicts: {pid, ppid, name, exe, cmdline, has_network, start}."""
    procs: List[Dict] = []
    net_pids = get_net_pids()

    if HAS_PSUTIL:
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
            try:
                info = p.info
                pid = info["pid"]
                has_net = (pid in net_pids) if net_pids is not None else _proc_has_net(p)
                cmdline_list = info.get("cmdline") or []
                procs.append({
                    "pid": pid,
                    "ppid": info.get("ppid") or 0,
                    "name": info.get("name") or "",
                    "exe": info.get("exe") or "",
                    "cmdline": " ".join(cmdline_list) if cmdline_list else "",
                    "argv": cmdline_list or None,
                    "has_network": has_net,
                    "start": int(info.get("create_time") or 0),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return procs

    if IS_WINDOWS:
        script = (
            "Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{"
            "ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; Name=$_.Name; "
            "ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine; "
            "Start=$(if ($_.CreationDate) { $_.CreationDate.ToFileTimeUtc() } else { 0 })} } "
            "| ConvertTo-Json -Compress"
        )
        for item in parse_json_list(run_powershell(script, timeout=30)):
            pid = int(item.get("ProcessId") or 0)
            procs.append({
                "pid": pid,
                "ppid": int(item.get("ParentProcessId") or 0),
                "name": item.get("Name") or "",
                "exe": item.get("ExecutablePath") or "",
                "cmdline": item.get("CommandLine") or "",
                "has_network": (pid in net_pids) if net_pids else False,
                "start": int(item.get("Start") or 0),
            })
    else:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                name = (entry / "comm").read_text(errors="ignore").strip()
                raw_cmd = (entry / "cmdline").read_bytes()
                cmdline = raw_cmd.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                stat = (entry / "stat").read_text(errors="ignore")
                rest = stat[stat.rfind(")") + 2:].split()
                ppid, start = int(rest[1]), int(rest[19])
                exe = ""
                try:
                    exe = os.readlink(entry / "exe")
                except OSError:
                    pass
                procs.append({
                    "pid": pid, "ppid": ppid, "name": name, "exe": exe,
                    "cmdline": cmdline, "has_network": False, "start": start,
                })
            except (OSError, ValueError, IndexError):
                continue

    return procs


def compute_self_pids(procs: List[Dict]) -> Set[int]:
    """This process, everything it spawned (PowerShell helpers), and launcher parents of this script."""
    me = os.getpid()
    by_pid = {p["pid"]: p for p in procs}
    children: Dict[int, List[int]] = {}
    for p in procs:
        children.setdefault(p.get("ppid", 0), []).append(p["pid"])

    result = {me}
    stack = [me]
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in result:
                result.add(child)
                stack.append(child)

    # Separate detector windows and background monitors use this exact script.
    for p in procs:
        if not _PY_RE.match(p["name"].lower()):
            continue
        try:
            args = shlex.split(p.get("cmdline") or "", posix=not IS_WINDOWS)
            if len(args) > 1 and Path(args[1].strip('"')).resolve() == SCRIPT_PATH:
                result.add(p["pid"])
        except (OSError, ValueError):
            continue

    cur = by_pid.get(me)
    for _ in range(6):
        parent = by_pid.get(cur.get("ppid")) if cur else None
        if not parent or parent["pid"] in result or SCRIPT_NAME not in (parent.get("cmdline") or "").lower():
            break
        result.add(parent["pid"])  # py.exe launcher / venv trampoline carrying the same command line
        cur = parent
    return result


# ============================================================================
# Persistence Scanner (Run keys, Winlogon, Startup folders, Scheduled Tasks, Services)
# ============================================================================

def assess_command(cmd: str) -> Optional[str]:
    """Return a risk reason if a startup/task/service command looks like a keylogger launcher."""
    if not cmd:
        return None
    hit = path_hit(cmd)
    if hit:
        return hit[1]
    low = cmd.lower()
    if any(kw in low for kw in SUSPICIOUS_NAME_KEYWORDS):
        return "Suspicious keyword in startup command"
    scripty = bool(SCRIPT_HOST_RE.search(cmd))
    for rx, _, desc, interp_only in _CMD_RE:
        if interp_only and not scripty:
            continue
        if rx.search(cmd):
            return desc
    if re.search(r"\b(?:pythonw|wscript|cscript|mshta)(?:\.exe)?\b", low):
        return "Startup entry launches a hidden/windowless script host"
    return None


def _registry_findings() -> List[PersistenceFinding]:
    try:
        import winreg  # type: ignore
    except ImportError:
        return []

    findings: List[PersistenceFinding] = []
    seen: Set[Tuple[str, str, str]] = set()
    base = r"Software\Microsoft\Windows\CurrentVersion"
    subkeys = [
        (base + r"\Run", "Run"),
        (base + r"\RunOnce", "RunOnce"),
        (base + r"\Policies\Explorer\Run", "Policies\\Explorer\\Run"),
    ]
    hives = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    views = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)  # also covers the WOW6432Node variants

    for hive, hive_label in hives:
        for subkey, short in subkeys:
            for view in views:
                try:
                    key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view)
                except OSError:
                    continue
                with key:
                    idx = 0
                    while True:
                        try:
                            val_name, val_data, _ = winreg.EnumValue(key, idx)
                        except OSError:
                            break
                        idx += 1
                        command = str(val_data)
                        if (hive_label == "HKCU" and subkey == SIGN_IN_KEY
                                and val_name == SIGN_IN_VALUE and command == sign_in_command()):
                            continue
                        reason = assess_command(command)
                        ident = (f"{hive_label}\\...\\{short}", val_name, command)
                        if reason and ident not in seen:
                            seen.add(ident)
                            findings.append(PersistenceFinding(ident[0], val_name, command, reason))

    # Winlogon Shell / Userinit tampering (HKLM)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            for value_name in ("Shell", "Userinit"):
                try:
                    data, _ = winreg.QueryValueEx(key, value_name)
                except OSError:
                    continue
                parts = [x.strip().lower() for x in str(data).split(",") if x.strip()]
                normal = ["explorer.exe"] if value_name == "Shell" else [SYSTEM32 + "userinit.exe"]
                if parts != normal:
                    findings.append(PersistenceFinding(
                        "HKLM\\...\\Winlogon", value_name, str(data),
                        f"Winlogon {value_name} differs from the Windows default"))
    except OSError:
        pass
    return findings


def _startup_folder_findings() -> List[PersistenceFinding]:
    findings: List[PersistenceFinding] = []
    folders: List[Tuple[Path, str]] = []
    appdata, progdata = os.environ.get("APPDATA"), os.environ.get("ProgramData")
    if appdata:
        folders.append((Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup", "User Startup folder"))
    if progdata:
        folders.append((Path(progdata) / "Microsoft/Windows/Start Menu/Programs/StartUp", "All-users Startup folder"))

    script_ext = {".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".ps1", ".py", ".pyw", ".hta", ".jar"}
    binary_ext = {".exe", ".scr", ".com", ".pif"}

    for folder, label in folders:
        try:
            items = list(folder.iterdir())
        except OSError:
            continue
        for item in items:
            ext = item.suffix.lower()
            if item.is_dir() or item.name.lower() == "desktop.ini":
                continue
            if ext in script_ext:
                findings.append(PersistenceFinding(label, item.name, str(item), "Script file placed in Startup folder"))
            elif ext in binary_ext:
                findings.append(PersistenceFinding(label, item.name, str(item), "Executable placed directly in Startup folder"))
        if any(i.suffix.lower() == ".lnk" for i in items):
            env = dict(os.environ)
            env["KLD_DIR"] = str(folder)
            script = (
                "$sh = New-Object -ComObject WScript.Shell; "
                "Get-ChildItem -LiteralPath $env:KLD_DIR -Filter *.lnk -ErrorAction SilentlyContinue | "
                "ForEach-Object { $l = $sh.CreateShortcut($_.FullName); "
                "[pscustomobject]@{File=$_.Name; Target=$l.TargetPath; Args=$l.Arguments} } | ConvertTo-Json -Compress"
            )
            for row in parse_json_list(run_powershell(script, timeout=20, env=env)):
                command = f"{row.get('Target') or ''} {row.get('Args') or ''}".strip()
                reason = assess_command(command)
                if reason:
                    findings.append(PersistenceFinding(label, str(row.get("File")), command, reason))
    return findings


def _scheduled_task_findings() -> List[PersistenceFinding]:
    script = (
        "Get-ScheduledTask -ErrorAction SilentlyContinue | "
        "Where-Object { $_.TaskPath -notlike '\\Microsoft\\Windows\\*' } | "
        "ForEach-Object { $t = $_; foreach ($a in $t.Actions) { [pscustomobject]@{"
        "Name=$t.TaskName; Path=$t.TaskPath; Exec=$a.Execute; Args=$a.Arguments} } } | ConvertTo-Json -Compress"
    )
    findings: List[PersistenceFinding] = []
    for row in parse_json_list(run_powershell(script, timeout=40)):
        command = f"{row.get('Exec') or ''} {row.get('Args') or ''}".strip()
        reason = assess_command(command)
        if reason:
            findings.append(PersistenceFinding(
                f"Scheduled Task {row.get('Path') or ''}", str(row.get("Name")), command, reason))
    return findings


def _service_findings() -> List[PersistenceFinding]:
    script = (
        "Get-CimInstance Win32_Service | Where-Object { $_.PathName } | "
        "Select-Object Name,PathName,StartMode | ConvertTo-Json -Compress"
    )
    findings: List[PersistenceFinding] = []
    for row in parse_json_list(run_powershell(script, timeout=30)):
        command = str(row.get("PathName") or "")
        reason = assess_command(command)
        if reason:
            findings.append(PersistenceFinding(
                f"Service ({row.get('StartMode') or '?'})", str(row.get("Name")), command, reason))
    return findings


def scan_windows_persistence() -> List[PersistenceFinding]:
    """Checks Run/RunOnce (64+32-bit views), Winlogon, Startup folders, Scheduled Tasks and Services."""
    if not IS_WINDOWS:
        return []
    findings: List[PersistenceFinding] = []
    for part in (_registry_findings, _startup_folder_findings, _scheduled_task_findings, _service_findings):
        try:
            findings.extend(part())
        except Exception:  # one broken source must not hide the others
            continue
    return findings


def persistence_key(p: PersistenceFinding) -> Tuple[str, str, str]:
    return (p.location, p.name, p.command)


# ============================================================================
# Risk Analysis Engine
# ============================================================================

def analyze_process(proc: Dict, ctx: ScanContext) -> Optional[ProcessFinding]:
    pid = proc["pid"]
    if pid in ctx.self_pids or pid == 0:
        return None

    name = proc["name"]
    name_lower = name.lower()
    exe_path = proc["exe"]
    exe_lower = exe_path.lower()
    if exe_lower.startswith("\\\\?\\"):
        exe_lower = exe_lower[4:]
    cmdline = proc["cmdline"]

    score = 0
    reasons: List[str] = []
    matched_apis: List[str] = []
    strong = False  # at least one content-based signal (not just "runs from a temp folder")

    # 0. Trusted names are only trusted at their expected location (an attacker can name a file anything).
    if not exe_lower and name_lower in KERNEL_PSEUDO_PROCESSES:
        return None

    if exe_lower:
        expected_dirs = PROCESS_EXPECTED_DIRS.get(name_lower)
        masquerading = False
        if expected_dirs is not None:
            if exe_dir(exe_lower) in expected_dirs:
                return None  # genuine system binary in its genuine folder
            masquerading = True
        elif name_lower in SYSTEMAPPS_PROCESSES:
            if exe_lower.startswith(SYSTEMAPPS_PREFIX):
                return None
            masquerading = True
        if masquerading:
            score += 50
            strong = True
            reasons.append(f"System process name '{name}' running from an unexpected location")

    is_trusted_path = any(exe_lower.startswith(p) for p in TRUSTED_EXE_PREFIXES)
    is_script_host = is_interpreter(name_lower)

    # 1. Process name keywords
    for kw in SUSPICIOUS_NAME_KEYWORDS:
        if kw in name_lower:
            score += 45
            strong = True
            reasons.append(f"Suspicious process name contains '{kw}'")
            break

    # 2. Execution path (the command line only counts for script hosts: it holds the script location)
    hit = path_hit(exe_path) if exe_path else None
    if hit is None and is_script_host:
        hit = path_hit(cmdline)
    if hit:
        score += hit[0]
        reasons.append(hit[1])

    # 3. Command-line patterns
    cmd_score = 0
    for rx, pts, desc, interp_only in _CMD_RE:
        if interp_only and not is_script_host:
            continue
        if rx.search(cmdline):
            cmd_score += pts
            reasons.append(desc)
    if cmd_score:
        score += min(60, cmd_score)
        strong = True

    if name_lower in WINDOWLESS_HOSTS:
        score += 15
        reasons.append(f"Windowless/script host execution ({name})")

    # 3b. Contents of the script being run (python x.py, powershell -File x.ps1 ...)
    script_path = None
    if is_script_host and cmdline:
        script_path = extract_script_path(cmdline, proc.get("argv"))
        if script_path:
            s_score, s_reasons = scan_script_file(script_path, ctx)
            if s_score:
                score += s_score
                strong = True
                reasons.extend(f"{r} [{os.path.basename(script_path)}]" for r in s_reasons)

    # 4. PE inspection: imports, dynamic APIs, packing, PyInstaller bundles, signature
    if exe_path and not is_trusted_path and exe_lower.endswith((".exe", ".scr")):
        stamp = _stamp(exe_path)
        if stamp:
            ck = (exe_lower, stamp[0], stamp[1])
            info = ctx.pe_cache.get(ck)
            if info is None:
                info = scan_pe(exe_path)
                ctx.pe_cache[ck] = info

            apis = sorted(set(info.apis) | set(info.dynamic_apis))
            api_score, api_note = score_api_imports(apis)
            pe_reasons: List[str] = []
            pe_score = 0
            if api_score:
                pe_score += api_score
                dyn = " [some resolved dynamically via GetProcAddress]" if info.dynamic_apis else ""
                pe_reasons.append(f"Imports keyboard-monitoring APIs: {', '.join(apis)}{api_note}{dyn}")
            if info.bundled_libs:
                pe_score += 40
                pe_reasons.append(f"PyInstaller bundle embeds keyboard-capture library: {', '.join(info.bundled_libs)}")

            if pe_score and ctx.check_signatures:
                status, subject = verify_signature(exe_path, ctx)
                if status == "Valid":
                    if publisher_names(subject) & TRUSTED_PUBLISHERS:
                        reasons.append(f"Valid signature from trusted publisher '{publisher_display(subject)}': binary indicators ignored")
                        pe_score, pe_reasons = 0, []
                    else:
                        pe_score //= 2
                        pe_reasons.append(f"Valid signature ({publisher_display(subject)}): binary score halved")
                elif status == "NotSigned":
                    pe_score += 10
                    pe_reasons.append("Binary is not digitally signed")
                elif status == "HashMismatch":
                    pe_score += 15
                    pe_reasons.append("Signature present but file was modified after signing (HashMismatch)")
                elif status == "NotTrusted":
                    pe_score += 10
                    pe_reasons.append("Binary signature is not trusted (self-signed, expired, or revoked)")

            if pe_score:
                score += pe_score
                strong = True
                matched_apis = apis
                reasons.extend(pe_reasons)
            if info.packed:
                score += 10
                reasons.append("Possibly packed/obfuscated (high entropy, very few imports)")

    # psutil uses Unix seconds. The Windows CIM fallback uses FILETIME.
    start = int(proc.get("start") or 0)
    if start >= FILETIME_UNIX_EPOCH:
        start = (start - FILETIME_UNIX_EPOCH) // 10_000_000
    behavior_score, behavior_reasons = ctx.behavior_findings.get((pid, start), (0, []))
    if behavior_score:
        score += behavior_score
        reasons.extend(behavior_reasons)
        strong = True

    # 5. Network exfiltration multiplier: only on top of a detection signal
    if proc["has_network"] and strong and score >= 25:
        score += 20
        reasons.append("Maintains active outbound network connection (possible exfiltration)")

    score = min(100, score)
    if score < FLAG_THRESHOLD:
        return None

    # 6. Whitelist (SHA-256 of the image). Checked last so we only hash files that would be flagged.
    wl_key = ""
    if ctx.whitelist is not None:
        wl_key = ctx.whitelist.key_for(proc) or ""
        if wl_key and ctx.whitelist.has(wl_key):
            return None

    severity = "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "MEDIUM"
    return ProcessFinding(
        pid=pid,
        name=name,
        exe_path=exe_path or "<unknown>",
        cmdline=cmdline[:300] if cmdline else "<unavailable>",
        score=score,
        severity=severity,
        reasons=reasons,
        matched_apis=matched_apis,
        has_network=proc["has_network"],
        start=int(proc.get("start") or 0),
        wl_key=wl_key,
        script_path=os.path.abspath(script_path) if script_path else "",
    )


def read_behavior_trace(path: Path, now: float) -> Dict[Tuple[int, int], Tuple[int, List[str]]]:
    """Score recent Windows API events supplied by an external collector."""
    try:
        with path.open("rb") as trace:
            size = trace.seek(0, os.SEEK_END)
            trace.seek(max(0, size - MAX_BEHAVIOR_TRACE_BYTES))
            data = trace.read(MAX_BEHAVIOR_TRACE_BYTES)
    except OSError as exc:
        warnings.warn(f"Unable to read behavior trace {path}: {exc}")
        return {}
    if size > MAX_BEHAVIOR_TRACE_BYTES:
        data = data.partition(b"\n")[2]  # The first line may start midway through a record.

    polls: Dict[Tuple[int, int], Set[float]] = {}
    hooks: Set[Tuple[int, int]] = set()
    for line in data.splitlines():
        if len(line) > 4096:
            continue
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(event, dict):
            continue
        pid, start, ts = (event.get(field) for field in ("pid", "process_start", "timestamp"))
        if (type(pid) is not int or pid <= 0 or type(start) is not int or start <= 0
                or type(ts) not in (int, float)
                or not max(start, now - BEHAVIOR_WINDOW_SECONDS) <= ts <= now):
            continue
        key = (pid, start)
        api = event.get("api")
        if isinstance(api, str) and api in POLL_APIS:
            polls.setdefault(key, set()).add(ts)
        if (isinstance(api, str) and api in HOOK_APIS
                and type(event.get("hook_id")) is int and event["hook_id"] in (2, 13)
                and type(event.get("thread_id")) is int and event["thread_id"] == 0
                and event.get("success") is True):
            hooks.add(key)

    findings = {}
    for key in polls.keys() | hooks:
        score, reasons = 0, []
        count = len(polls.get(key, ()))
        if count >= 100:
            score += 35
            reasons.append(f"Runtime: {count} keyboard state polls in the last {BEHAVIOR_WINDOW_SECONDS}s")
        if key in hooks:
            score += 45
            reasons.append("Runtime: successfully installed a global Windows keyboard hook")
        if score:
            findings[key] = (score, reasons)
    return findings


def scan_processes(ctx: ScanContext) -> Tuple[int, List[ProcessFinding]]:
    if ctx.whitelist is not None:
        ctx.whitelist.load()
    procs = get_processes_snapshot()
    by_pid = {proc["pid"]: proc for proc in procs}
    behavior = read_behavior_trace(ctx.behavior_trace, time.time()) if ctx.behavior_trace else {}
    scan_ctx = replace(ctx, self_pids=compute_self_pids(procs), behavior_findings=behavior)
    findings: Dict[int, ProcessFinding] = {}
    for proc in procs:
        try:
            f = analyze_process(proc, scan_ctx)
        except Exception:  # a single unreadable process must never abort the whole scan
            f = None
        if f is None:
            continue
        group = f.pid
        # One-file Windows bundles can run a launcher and a child from the same image.
        if IS_WINDOWS and f.exe_path.lower().endswith(".exe"):
            path = ntpath.normcase(ntpath.normpath(f.exe_path))
            parent = by_pid.get(proc.get("ppid"))
            if (parent and 0 < (parent.get("start") or 0) <= f.start
                    and ntpath.normcase(ntpath.normpath(parent.get("exe") or "")) == path):
                group = parent["pid"]
        previous = findings.get(group)
        if previous is None or (f.score, f.pid != group) > (previous.score, previous.pid != group):
            findings[group] = f
    return len(procs), list(findings.values())


# ============================================================================
# Alerting & Process Control
# ============================================================================

def play_alert_sound() -> None:
    """Non-blocking beep (Beep() blocks for its duration, which would freeze the GUI)."""
    if not IS_WINDOWS:
        return

    def _beep() -> None:
        try:
            import winsound  # type: ignore
            winsound.Beep(1200, 220)
        except Exception:
            pass

    threading.Thread(target=_beep, daemon=True).start()


def launch_alert_window(mode: str, payload: dict) -> None:
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = str(pythonw) if pythonw.is_file() else sys.executable
    child = subprocess.Popen(
        [interpreter, str(SCRIPT_PATH), mode],
        stdin=subprocess.PIPE,
        cwd=SCRIPT_PATH.parent,
        creationflags=NO_WINDOW,
    )
    with child.stdin as stream:
        stream.write(json.dumps(payload).encode("ascii"))


def show_detection_popup(groups: List[Tuple[str, str]], sound: bool = True,
                         parent=None, open_processes=None, findings=None) -> None:
    import ctypes
    from ctypes import wintypes
    import tkinter as tk
    from tkinter import messagebox
    from tkinter.scrolledtext import ScrolledText

    root = tk.Toplevel(parent) if parent is not None else tk.Tk()
    root.withdraw()
    root.title("Keylogger Detector")
    root.attributes("-topmost", True)
    root.configure(bg="#f1f5f9")

    def open_detector() -> None:
        if open_processes is not None:
            root.destroy()
            open_processes()
            return
        try:
            if findings is not None:
                launch_alert_window("--alert-viewer", {"findings": findings})
            else:
                subprocess.Popen([sys.executable, str(SCRIPT_PATH), "--viewer"], cwd=SCRIPT_PATH.parent)
        except OSError as exc:
            messagebox.showerror("Could not open Keylogger Detector", str(exc), parent=root)
        else:
            root.destroy()

    heading = " · ".join(title for title, _ in groups)
    tk.Label(root, text=heading, font=("Segoe UI", 13, "bold"), anchor="w",
             justify="left", wraplength=460, bg="#f1f5f9").pack(fill="x", padx=16, pady=(14, 8))
    buttons = tk.Frame(root, bg="#f1f5f9")
    buttons.pack(fill="x", padx=16, pady=12)

    def position_popup(window, center: bool = False) -> None:
        window.update_idletasks()
        area = wintypes.RECT()
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(area), 0):
            left, top, right, bottom = area.left, area.top, area.right, area.bottom
        else:
            left, top, right, bottom = 0, 0, window.winfo_screenwidth(), window.winfo_screenheight()
        width, height = window.winfo_reqwidth(), window.winfo_reqheight()
        if center:
            x = max(left, left + (right - left - width) // 2)
            y = max(top, top + (bottom - top - height) // 2)
        else:
            x = max(left, right - width - 16)
            y = max(top, bottom - height - 40)
        window.geometry(f"{x:+d}{y:+d}")

    def view_details() -> None:
        detail_window = tk.Toplevel(root)
        detail_window.withdraw()
        detail_window.title("Suspicious Process Details")
        detail_window.attributes("-topmost", True)
        tk.Label(detail_window, text=heading, font=("Segoe UI", 13, "bold"),
                 wraplength=560).pack(padx=16, pady=(14, 8))
        details = ScrolledText(detail_window, width=68, height=15, wrap="word",
                               font=("Segoe UI", 10), padx=8, pady=6)
        details.insert("1.0", "\n\n".join(body for _, body in groups))
        details.configure(state="disabled")
        details.pack(fill="both", expand=True, padx=16)
        actions = tk.Frame(detail_window)
        actions.pack(fill="x", padx=16, pady=12)
        tk.Button(actions, text="Open Keylogger Detector", command=open_detector).pack(side="left")
        tk.Button(actions, text="Dismiss", command=root.destroy).pack(side="right")
        detail_window.protocol("WM_DELETE_WINDOW", root.destroy)
        detail_window.bind("<Escape>", lambda _event: root.destroy())
        position_popup(detail_window, center=True)
        root.withdraw()
        detail_window.deiconify()
        detail_window.lift()

    tk.Button(buttons, text="View Details", command=view_details).pack(side="left")
    tk.Button(buttons, text="Dismiss", command=root.destroy).pack(side="right")
    root.bind("<Escape>", lambda _event: root.destroy())

    position_popup(root)
    root.deiconify()
    if sound:
        root.after_idle(play_alert_sound)
    if parent is None:
        root.mainloop()


def notify_new_findings(findings: List[ProcessFinding], sound: bool = True,
                        parent=None, open_processes=None) -> None:
    if not IS_WINDOWS or not findings:
        return

    groups = []
    for severities, title in (
        ({"HIGH", "CRITICAL"}, "high or critical keylogger finding"),
        ({"MEDIUM"}, "possible keylogger"),
    ):
        matches = [finding for finding in findings if finding.severity in severities]
        if not matches:
            continue
        heading = f"{len(matches)} {title}{'' if len(matches) == 1 else 's'}"
        lines = []
        for finding in sorted(matches, key=lambda item: item.score, reverse=True):
            lines.append(f"{finding.severity} · {finding.file_name} · PID {finding.pid} · Score {finding.score}/100")
            lines.extend(f"• {reason}" for reason in finding.reasons)
            lines.append("")
        groups.append((heading, "\n".join(lines).rstrip()))

    if not groups:
        return
    if parent is not None:
        show_detection_popup(groups, sound, parent, open_processes)
        return
    try:
        launch_alert_window("--alert-popup", {
            "groups": groups,
            "sound": sound,
            "findings": [asdict(finding) for finding in findings],
        })
    except OSError as exc:
        print(f"[!] Desktop notification failed: {exc}", file=sys.stderr)


def append_finding_log(finding: ProcessFinding, log_file: Path) -> None:
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(finding), ensure_ascii=False) + "\n")
    except OSError:
        pass


def trigger_alert(finding: ProcessFinding, log_file: Path, sound: bool = True) -> None:
    banner = (
        f"\n[!] {finding.severity} ALERT (Score: {finding.score}/100) — "
        f"PID {finding.pid} ({finding.name})\n"
        f"    Path   : {finding.exe_path}\n"
        f"    Cmdline: {finding.cmdline}\n"
        f"    Reasons:\n"
        + "\n".join(f"      - {r}" for r in finding.reasons)
    )
    print(banner)
    if sound and finding.severity in {"HIGH", "CRITICAL"}:
        play_alert_sound()
    append_finding_log(finding, log_file)


def terminate_process(pid: int, expected_start: int, expected_exe: str) -> Tuple[bool, str]:
    """
    Terminate a flagged process only if the PID still refers to the SAME process
    (PIDs are reused by Windows, so a stale PID could belong to something innocent now).
    """
    if pid <= 4 or pid == os.getpid():
        return False, "Refusing to terminate a protected or own process."
    exe_known = expected_exe and expected_exe != "<unknown>"

    if HAS_PSUTIL:
        try:
            p = psutil.Process(pid)
            if expected_start and abs(int(p.create_time()) - expected_start) > 1:
                return False, "The PID now belongs to a different process (PID was reused). Nothing was terminated."
            try:
                if exe_known and p.exe() and p.exe().lower() != expected_exe.lower():
                    return False, "The process image changed. Nothing was terminated."
            except psutil.AccessDenied:
                pass
            p.terminate()
            try:
                p.wait(timeout=3)
            except psutil.TimeoutExpired:
                p.kill()
            return True, "Process terminated."
        except psutil.NoSuchProcess:
            return False, "The process is no longer running."
        except psutil.AccessDenied:
            return False, "Access denied. Try running as Administrator."
        except Exception as exc:
            return False, f"Failed: {exc}"

    current = next((p for p in get_processes_snapshot() if p["pid"] == pid), None)
    if current is None:
        return False, "The process is no longer running."
    if expected_start and current["start"] != expected_start:
        return False, "The PID now belongs to a different process (PID was reused). Nothing was terminated."
    if IS_WINDOWS:
        res = subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, creationflags=NO_WINDOW)
        return (res.returncode == 0, "Process terminated." if res.returncode == 0
                else "taskkill failed. Try running as Administrator.")
    try:
        os.kill(pid, 15)
        return True, "Process terminated."
    except OSError as exc:
        return False, f"Failed: {exc}"


def _is_protected_delete_path(path: str) -> bool:
    """Return True if deleting this path could damage the OS, installed runtime, or this tool."""
    if Path(path) in {SCRIPT_PATH, Path(sys.executable).resolve()}:
        return True

    low = path.lower().replace("/", "\\")
    if low.startswith("\\\\?\\"):
        low = low[4:]
    if any(low.startswith(p) for p in TRUSTED_EXE_PREFIXES):
        return True
    if low.startswith(SYSTEMAPPS_PREFIX) or low.startswith(tuple(p + "\\" for p in _program_files_dirs())):
        return True
    # Protect the Windows directory except for its temporary files.
    if IS_WINDOWS and (exe_dir(low) == SYSTEM_ROOT + "\\"
                       or (low.startswith(SYSTEM_ROOT + "\\")
                           and not low.startswith(SYSTEM_ROOT + "\\temp\\"))):
        return True
    if not IS_WINDOWS:
        posix_low = path.lower()
        if posix_low.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/usr/lib/", "/etc/", "/boot/", "/opt/",
                                 "/usr/local/", "/lib64/", "/usr/lib64/")):
            return True
    return False


def resolve_delete_target(finding: ProcessFinding) -> Tuple[Path, Tuple[int, ...]]:
    if not finding.start or finding.exe_path in {"", "<unknown>"}:
        raise OSError("The process identity could not be verified.")
    if is_interpreter(finding.name.lower()) and not finding.script_path:
        raise OSError("The flagged interpreter has no identified script file.")
    target = Path(finding.file_path)
    if not target.is_absolute() or target.resolve(strict=True) != target:
        raise OSError(f"A direct, absolute file path is required: {target}")
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or _is_protected_delete_path(str(target)):
        raise OSError(f"File is protected or is not a regular file: {target}")
    return target, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _stop_other_instances_of_target(target: Path, exclude_pid: int) -> None:
    """Terminate any other running processes executing the exact same target binary."""
    if not IS_WINDOWS or target.suffix.lower() != ".exe":
        return
    target_low = str(target).lower()
    if HAS_PSUTIL:
        for proc in psutil.process_iter(["pid", "exe"]):
            try:
                pid = proc.info.get("pid")
                exe = proc.info.get("exe") or ""
                if pid and pid > 4 and pid != os.getpid() and pid != exclude_pid:
                    if exe.lower() == target_low:
                        proc.kill()
                        proc.wait(timeout=3)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired, OSError):
                continue
    else:
        for proc in get_processes_snapshot():
            pid = proc.get("pid", 0)
            exe = (proc.get("exe") or "").lower()
            if pid > 4 and pid != os.getpid() and pid != exclude_pid and exe == target_low:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/F"],
                    capture_output=True,
                    creationflags=NO_WINDOW,
                )


def _schedule_delete_on_reboot(target: Path) -> bool:
    """Schedule file removal on next Windows reboot if a kernel/AV handle remains open."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
        return bool(
            ctypes.windll.kernel32.MoveFileExW(
                str(target),
                None,
                MOVEFILE_DELAY_UNTIL_REBOOT,
            )
        )
    except Exception:
        return False


def delete_threat(finding: ProcessFinding, target: Path, expected: Tuple[int, ...]) -> Tuple[bool, bool, str]:
    try:
        if resolve_delete_target(finding) != (target, expected):
            return False, False, "The selected file changed before termination."
    except (OSError, RuntimeError) as exc:
        return False, False, str(exc)

    stopped, message = terminate_process(finding.pid, finding.start, finding.exe_path)
    if not stopped:
        return False, False, message

    # Stop any sibling/bootloader processes running from the exact same .exe path
    _stop_other_instances_of_target(target, finding.pid)

    # Clear read-only attribute if present
    try:
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass

    last_error: Optional[Exception] = None
    for attempt in range(12):
        try:
            if resolve_delete_target(finding) != (target, expected):
                return True, False, "Process terminated. The selected file changed."
            target.unlink()
            return True, True, f"Process terminated and file deleted: {target}"
        except PermissionError as exc:
            last_error = exc
            _stop_other_instances_of_target(target, finding.pid)
            time.sleep(0.25)
        except (OSError, RuntimeError) as exc:
            return True, False, f"Process terminated. File deletion failed: {exc}"

    if _schedule_delete_on_reboot(target):
        return (
            True,
            True,
            f"Process terminated. File handle is still locked by Windows; scheduled for automatic deletion on reboot: {target}",
        )

    return True, False, f"Process terminated. File deletion failed (try running detector as Administrator): {last_error}"

# ============================================================================
# Tkinter SOC GUI
# ============================================================================

def select_file_in_explorer(path: str) -> None:
    # Explorer expects /select, followed by a quoted path in the command line.
    subprocess.Popen(f'explorer.exe /select,"{os.path.normpath(path)}"')


def launch_gui(log_file: Path, ctx: ScanContext, auto_monitor: bool = True,
               alert_findings: Optional[List[ProcessFinding]] = None) -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError as exc:
        print(f"[-] Tkinter is not available in this Python environment: {exc}")
        print("[*] Falling back to CLI scan mode...")
        run_scan(log_file, ctx)
        return

    # Dark SOC Theme Palette
    BG_DARK = "#0f172a"
    BG_CARD = "#1e293b"
    BG_INPUT = "#0b1220"
    FG_TEXT = "#e2e8f0"
    FG_MUTED = "#94a3b8"
    ACCENT = "#38bdf8"
    AMBER = "#f59e0b"
    ORANGE = "#f97316"
    RED = "#ef4444"
    BORDER = "#334155"

    root = tk.Tk()
    root.title("Keylogger Detector — SOC Process & API Hook Monitor")
    root.geometry("1120x740")
    root.minsize(920, 620)
    root.configure(bg=BG_DARK)

    # Shared state (only touched from the main thread, except `settings` which is read by the monitor thread)
    ui_queue: queue.Queue = queue.Queue()
    monitor_stop_event = threading.Event()
    monitoring_active = False
    findings_by_key: Dict[str, ProcessFinding] = {}
    persistence_state: List[PersistenceFinding] = []
    seen_persistence: Set[Tuple[str, str, str]] = set()
    persistence_baseline = False
    banner_job = None
    last_priorities: Set[str] = set()
    settings = {"interval": 3.0}  # plain value so worker threads never touch Tk variables

    # ttk Styling
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background=BG_DARK)
    style.configure("TLabel", background=BG_DARK, foreground=FG_TEXT, font=("Segoe UI", 10))
    style.configure("TNotebook", background=BG_DARK, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG_CARD, foreground=FG_MUTED, padding=(14, 7), font=("Segoe UI", 10, "bold"))
    style.map("TNotebook.Tab", background=[("selected", "#334155")], foreground=[("selected", FG_TEXT)])
    style.configure("Treeview", background=BG_CARD, foreground=FG_TEXT, fieldbackground=BG_CARD,
                    rowheight=28, borderwidth=0, font=("Consolas", 9))
    style.configure("Treeview.Heading", background="#0b1220", foreground=ACCENT,
                    font=("Segoe UI", 9, "bold"), relief="flat")
    style.map("Treeview", background=[("selected", "#334155")], foreground=[("selected", "#ffffff")])

    # ── Header & Controls ────────────────────────────────────────────────────
    header = tk.Frame(root, bg=BG_CARD, padx=16, pady=12, highlightbackground=BORDER, highlightthickness=1)
    header.pack(fill="x", padx=12, pady=(12, 8))

    title_box = tk.Frame(header, bg=BG_CARD)
    title_box.pack(side="left")
    tk.Label(title_box, text="KEYLOGGER DETECTOR", bg=BG_CARD, fg=ACCENT,
             font=("Segoe UI", 14, "bold")).pack(anchor="w")
    tk.Label(
        title_box,
        text=(f"Host: {socket.gethostname()}  |  OS: {sys.platform}  |  psutil: {'Active' if HAS_PSUTIL else 'Fallback'}"
              f"  |  Signatures: {'On' if ctx.check_signatures and IS_WINDOWS else 'Off'}"),
        bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(anchor="w")

    controls = tk.Frame(header, bg=BG_CARD)
    controls.pack(side="right")

    sound_var = tk.BooleanVar(value=True)
    interval_var = tk.StringVar(value="3.0")

    def on_interval_change(*_args) -> None:
        try:
            settings["interval"] = max(1.0, float(interval_var.get()))
        except (ValueError, tk.TclError):
            pass  # keep the last valid value while the user is mid-edit

    interval_var.trace_add("write", on_interval_change)

    tk.Checkbutton(controls, text="Sound Alert", variable=sound_var, bg=BG_CARD, fg=FG_TEXT,
                   selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_TEXT,
                   font=("Segoe UI", 9)).pack(side="left", padx=(0, 10))
    tk.Label(controls, text="Interval (s):", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(side="left")
    tk.Spinbox(controls, from_=1.0, to=60.0, increment=0.5, textvariable=interval_var, width=5,
               bg=BG_INPUT, fg=FG_TEXT, buttonbackground=BORDER, relief="flat",
               font=("Consolas", 10)).pack(side="left", padx=(4, 12))

    def make_button(parent, text, bg, active, fg="#ffffff", **kw):
        return tk.Button(parent, text=text, bg=bg, fg=fg, activebackground=active, activeforeground="#ffffff",
                         relief="flat", font=("Segoe UI", 9, "bold"), cursor="hand2", **kw)

    scan_btn = make_button(controls, "Scan Now", "#0284c7", "#0369a1", padx=14, pady=6)
    scan_btn.pack(side="left", padx=4)
    monitor_btn = make_button(controls, "Start Monitor", "#16a34a", "#15803d", padx=14, pady=6)
    monitor_btn.pack(side="left", padx=4)
    export_btn = make_button(controls, "Export JSON", "#334155", "#475569", fg=FG_TEXT, padx=12, pady=6)
    export_btn.pack(side="left", padx=4)

    if IS_WINDOWS:
        startup_menu = tk.Menu(root)
        startup_options = tk.Menu(startup_menu, tearoff=False)

        def on_sign_in_change(enable: bool) -> None:
            try:
                configure_sign_in(enable)
            except OSError as exc:
                messagebox.showerror("Start at Sign-in", str(exc), parent=root)
            else:
                status = "Enabled" if enable else "Disabled"
                messagebox.showinfo("Start at Sign-in", f"{status} for your Windows account.", parent=root)

        startup_options.add_command(label="Enable Start at Sign-in", command=lambda: on_sign_in_change(True))
        startup_options.add_command(label="Disable Start at Sign-in", command=lambda: on_sign_in_change(False))
        startup_menu.add_cascade(label="Startup", menu=startup_options)
        root.configure(menu=startup_menu)

    # ── KPI Summary Row ──────────────────────────────────────────────────────
    kpi_row = tk.Frame(root, bg=BG_DARK)
    kpi_row.pack(fill="x", padx=12, pady=(0, 8))
    kpi_vars = {k: tk.StringVar(value=v) for k, v in
                {"status": "IDLE", "scanned": "0", "flagged": "0", "critical": "0", "persistence": "0"}.items()}

    def make_kpi(title: str, var: tk.StringVar, color: str) -> None:
        card = tk.Frame(kpi_row, bg=BG_CARD, padx=14, pady=10, highlightbackground=BORDER, highlightthickness=1)
        card.pack(side="left", fill="x", expand=True, padx=4)
        tk.Label(card, text=title, bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(card, textvariable=var, bg=BG_CARD, fg=color, font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(2, 0))

    make_kpi("ENGINE STATUS", kpi_vars["status"], ACCENT)
    make_kpi("PROCESSES CHECKED", kpi_vars["scanned"], FG_TEXT)
    make_kpi("SUSPICIOUS FLAGGED", kpi_vars["flagged"], AMBER)
    make_kpi("HIGH / CRITICAL", kpi_vars["critical"], RED)
    make_kpi("STARTUP ENTRIES", kpi_vars["persistence"], ORANGE)

    # ── Notebook Tabs ────────────────────────────────────────────────────────
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=12, pady=(0, 8))
    tab_procs, tab_persist, tab_logs = ttk.Frame(notebook), ttk.Frame(notebook), ttk.Frame(notebook)
    notebook.add(tab_procs, text="Suspicious Processes")
    tab_whitelist = ttk.Frame(notebook)
    notebook.add(tab_persist, text="Startup & Persistence")
    notebook.add(tab_whitelist, text="Whitelist")
    notebook.add(tab_logs, text="Live Event Log")

    # Non-blocking alert banner (replaces the modal messagebox that froze the monitor)
    alert_banner = tk.Label(root, text="", bg="#7f1d1d", fg="#fecaca", font=("Segoe UI", 10, "bold"),
                            anchor="w", padx=14, pady=8, cursor="hand2")
    def show_suspicious_processes(_event=None) -> None:
        notebook.select(tab_procs)
        priority = max(
            (f for f in findings_by_key.values() if f.severity in {"HIGH", "CRITICAL"}),
            key=lambda f: f.score, default=None,
        )
        if priority:
            row = proc_key(priority.pid, priority.start)
            proc_tree.selection_set(row)
            proc_tree.focus(row)
            proc_tree.see(row)
        root.deiconify()
        root.lift()
        root.attributes("-topmost", True)
        root.after_idle(lambda: root.attributes("-topmost", False))

    alert_banner.bind("<Button-1>", show_suspicious_processes)

    def hide_banner() -> None:
        nonlocal banner_job
        banner_job = None
        alert_banner.pack_forget()

    def show_banner(msg: str) -> None:
        nonlocal banner_job
        alert_banner.configure(text="⚠  " + msg + "   (click to view)")
        if not alert_banner.winfo_ismapped():
            alert_banner.pack(fill="x", padx=12, pady=(0, 8), before=notebook)
        if banner_job is not None:
            root.after_cancel(banner_job)
        banner_job = root.after(12000, hide_banner)

    # Tab 1: Processes Treeview
    tree_frame = tk.Frame(tab_procs, bg=BG_DARK)
    tree_frame.pack(fill="both", expand=True, pady=(6, 6))
    proc_cols = ("severity", "score", "pid", "name", "file", "network", "apis", "path")
    proc_tree = ttk.Treeview(tree_frame, columns=proc_cols, show="headings", selectmode="browse")
    for col_id, label, width in [
        ("severity", "Severity", 90), ("score", "Score", 65), ("pid", "PID", 75),
        ("name", "Process Name", 125), ("file", "File Name", 160),
        ("network", "Outbound Net", 90), ("apis", "Matched APIs / Indicators", 230),
        ("path", "File Path", 245),
    ]:
        proc_tree.heading(col_id, text=label)
        proc_tree.column(col_id, width=width, anchor="w")
    proc_tree.tag_configure("CRITICAL", foreground="#fca5a5", background="#450a0a")
    proc_tree.tag_configure("HIGH", foreground="#fdba74", background="#431407")
    proc_tree.tag_configure("MEDIUM", foreground="#fde047", background="#422006")
    proc_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=proc_tree.yview)
    proc_tree.configure(yscrollcommand=proc_scroll.set)
    proc_tree.pack(side="left", fill="both", expand=True)
    proc_scroll.pack(side="right", fill="y")

    inspector = tk.Frame(tab_procs, bg=BG_CARD, padx=12, pady=10, highlightbackground=BORDER, highlightthickness=1)
    inspector.pack(fill="x", pady=(0, 4))
    insp_top = tk.Frame(inspector, bg=BG_CARD)
    insp_top.pack(fill="x")
    tk.Label(insp_top, text="FORENSIC DETAILS & ACTIONS", bg=BG_CARD, fg=ACCENT,
             font=("Segoe UI", 9, "bold")).pack(side="left")
    action_btns = tk.Frame(insp_top, bg=BG_CARD)
    action_btns.pack(side="right")
    kill_btn = make_button(action_btns, "Terminate PID", "#dc2626", "#b91c1c", padx=10, pady=4)
    kill_btn.pack(side="left", padx=4)
    delete_btn = make_button(action_btns, "Delete Threat", "#dc2626", "#b91c1c", padx=10, pady=4)
    delete_btn.pack(side="left", padx=4)
    whitelist_btn = make_button(action_btns, "Whitelist Process", "#475569", "#334155", padx=10, pady=4)
    whitelist_btn.pack(side="left", padx=4)
    open_dir_btn = make_button(action_btns, "Open Location", "#0284c7", "#0369a1", padx=10, pady=4)
    open_dir_btn.pack(side="left", padx=4)
    details_text = tk.Text(inspector, height=7, bg=BG_INPUT, fg=FG_TEXT, relief="flat",
                           font=("Consolas", 9), wrap="word", state="disabled", padx=8, pady=6)
    details_text.pack(fill="x", pady=(8, 0))

    # Startup & Persistence
    persist_tree = ttk.Treeview(tab_persist, columns=("location", "name", "command", "reason"), show="headings")
    for col_id, label, width in [
        ("location", "Location", 190), ("name", "Entry Name", 160),
        ("command", "Command / Target", 400), ("reason", "Risk Reason", 270),
    ]:
        persist_tree.heading(col_id, text=label)
        persist_tree.column(col_id, width=width, anchor="w")
    persist_tree.pack(fill="both", expand=True, pady=6)

    # Live Event Log
    log_text = tk.Text(tab_logs, bg=BG_INPUT, fg=FG_TEXT, relief="flat", font=("Consolas", 9),
                       wrap="word", state="disabled", padx=10, pady=8)
    log_text.pack(fill="both", expand=True, pady=6)

    whitelist_actions = ttk.Frame(tab_whitelist)
    whitelist_actions.pack(side="bottom", fill="x", pady=(0, 6))
    remove_whitelist_btn = make_button(whitelist_actions, "Remove from Whitelist", "#475569", "#334155",
                                       padx=16, pady=8)
    remove_whitelist_btn.configure(font=("Segoe UI", 10, "bold"))
    remove_whitelist_btn.pack(side="right")
    whitelist_tree = ttk.Treeview(tab_whitelist, columns=("name", "path", "added"),
                                  show="headings", selectmode="browse")
    for col_id, label, width in [
        ("name", "Process Name", 200),
        ("path", "Executable Path", 560),
        ("added", "Date Added", 180),
    ]:
        whitelist_tree.heading(col_id, text=label)
        whitelist_tree.column(col_id, width=width, anchor="w")
    whitelist_scroll = ttk.Scrollbar(tab_whitelist, orient="vertical", command=whitelist_tree.yview)
    whitelist_tree.configure(yscrollcommand=whitelist_scroll.set)
    whitelist_scroll.pack(side="right", fill="y", pady=6)
    whitelist_tree.pack(side="left", fill="both", expand=True, pady=6)

    def refresh_whitelist_table() -> None:
        whitelist_tree.delete(*whitelist_tree.get_children())
        if ctx.whitelist is None:
            return
        for key, entry in ctx.whitelist.entries.items():
            whitelist_tree.insert("", "end", iid=key, values=(
                entry.get("name", ""), entry.get("path", ""), entry.get("added", ""),
            ))

    refresh_whitelist_table()

    # ── Helper Functions ─────────────────────────────────────────────────────
    def append_ui_log(msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        log_text.configure(state="normal")
        log_text.insert("end", f"[{ts}] {msg}\n")
        log_text.see("end")
        log_text.configure(state="disabled")

    def set_details(text: str) -> None:
        details_text.configure(state="normal")
        details_text.delete("1.0", "end")
        details_text.insert("1.0", text)
        details_text.configure(state="disabled")

    def refresh_proc_table() -> None:
        selected = proc_tree.selection()
        selected_iid = selected[0] if selected else None
        proc_tree.delete(*proc_tree.get_children())
        ordered = sorted(findings_by_key.items(), key=lambda kv: kv[1].score, reverse=True)
        high_crit = 0
        for key, f in ordered:
            if f.severity in {"HIGH", "CRITICAL"}:
                high_crit += 1
            indicators = ", ".join(f.matched_apis) if f.matched_apis else (f.reasons[0] if f.reasons else "-")
            proc_tree.insert("", "end", iid=key, tags=(f.severity,), values=(
                f.severity, f"{f.score}/100", f.pid, f.name, f.file_name,
                "YES" if f.has_network else "NO", indicators, f.file_path))
        kpi_vars["flagged"].set(str(len(ordered)))
        kpi_vars["critical"].set(str(high_crit))
        if selected_iid and proc_tree.exists(selected_iid):
            proc_tree.selection_set(selected_iid)
        elif selected_iid:
            set_details("")

    def get_selected() -> Tuple[Optional[str], Optional[ProcessFinding]]:
        sel = proc_tree.selection()
        if not sel:
            return None, None
        return sel[0], findings_by_key.get(sel[0])

    def on_row_select(_event=None) -> None:
        _, f = get_selected()
        if not f:
            return
        set_details("\n".join([
            f"PID: {f.pid}   |   Name: {f.name}   |   Severity: {f.severity} ({f.score}/100)   |   Detected: {f.timestamp}",
            f"File       : {f.file_path}",
            f"Executable : {f.exe_path}",
            f"CommandLine: {f.cmdline}",
            f"Outbound   : {'Active external socket' if f.has_network else 'None observed'}",
            "Indicators :",
            *[f"  - {r}" for r in f.reasons],
        ]))

    proc_tree.bind("<<TreeviewSelect>>", on_row_select)

    def refresh_persist_table() -> None:
        persist_tree.delete(*persist_tree.get_children())
        for p in persistence_state:
            persist_tree.insert("", "end", values=(p.location, p.name, p.command, p.reason))
        kpi_vars["persistence"].set(str(len(persistence_state)))

    # ── Worker Threads ───────────────────────────────────────────────────────
    def perform_scan_worker(full: bool, with_persistence: bool,
                            removed_entry: Optional[Tuple[str, str]] = None) -> None:
        try:
            total, findings = scan_processes(ctx)
            ui_queue.put(("scan_result", full, total, findings, removed_entry))
            if with_persistence:
                ui_queue.put(("persistence_result", scan_windows_persistence()))
        except Exception as exc:  # report instead of silently killing the thread
            ui_queue.put(("error", full, f"{type(exc).__name__}: {exc}"))
            if removed_entry is not None:
                ui_queue.put(("whitelist_rescan_error", removed_entry[1]))

    def on_scan_click() -> None:
        kpi_vars["status"].set("SCANNING...")
        scan_btn.configure(state="disabled")
        append_ui_log("Starting full process, PE import, script & persistence scan...")
        threading.Thread(target=perform_scan_worker, args=(True, True), daemon=True).start()

    def monitor_loop_worker() -> None:
        last_persistence = 0.0
        while not monitor_stop_event.is_set():
            now = time.time()
            due = now - last_persistence >= PERSISTENCE_RESCAN_SECONDS
            if due:
                last_persistence = now
            perform_scan_worker(False, due)
            monitor_stop_event.wait(settings["interval"])

    def on_monitor_toggle() -> None:
        nonlocal monitoring_active
        if not monitoring_active:
            monitoring_active = True
            monitor_stop_event.clear()
            monitor_btn.configure(text="Stop Monitor", bg="#dc2626", activebackground="#b91c1c")
            kpi_vars["status"].set("MONITORING")
            append_ui_log("Real-time monitoring started.")
            threading.Thread(target=monitor_loop_worker, daemon=True).start()
        else:
            monitoring_active = False
            monitor_stop_event.set()
            monitor_btn.configure(text="Start Monitor", bg="#16a34a", activebackground="#15803d")
            kpi_vars["status"].set("IDLE")
            append_ui_log("Real-time monitoring stopped.")

    def on_kill_click() -> None:
        key, f = get_selected()
        if not f:
            messagebox.showinfo("No Selection", "Select a flagged process from the table first.")
            return
        if not messagebox.askyesno("Confirm Terminate", f"Terminate PID {f.pid} ({f.name})?"):
            return
        ok, msg = terminate_process(f.pid, f.start, f.exe_path)
        if ok:
            findings_by_key.pop(key, None)
            refresh_proc_table()
            set_details("")
            append_ui_log(f"Terminated PID {f.pid} ({f.name}).")
        else:
            append_ui_log(f"Terminate failed for PID {f.pid} ({f.name}): {msg}")
            messagebox.showerror("Failed", msg)

    def on_delete_click() -> None:
        key, finding = get_selected()
        if not finding:
            messagebox.showinfo("No Selection", "Select a flagged process from the table first.")
            return
        try:
            target, expected = resolve_delete_target(finding)
        except (OSError, RuntimeError) as exc:
            messagebox.showerror("Cannot Delete", str(exc))
            return
        if not messagebox.askyesno(
                "Confirm Delete Threat",
                f"Terminate PID {finding.pid} and permanently delete this file?\n\n{target}",
                icon="warning"):
            return
        stopped, deleted, message = delete_threat(finding, target, expected)
        append_ui_log(message)
        if stopped:
            findings_by_key.pop(key, None)
            refresh_proc_table()
            set_details("")
        if not deleted:
            messagebox.showwarning("Delete Threat", message)

    def on_whitelist_click() -> None:
        _, f = get_selected()
        if not f:
            messagebox.showinfo("No Selection", "Select a flagged process from the table first.")
            return
        if ctx.whitelist is None or not f.wl_key:
            messagebox.showerror("Cannot whitelist", "The executable could not be read/hashed, so it cannot be whitelisted safely.")
            return
        if not messagebox.askyesno(
                "Confirm Whitelist",
                f"Trust this exact file (SHA-256 {f.wl_key[:16]}...)?\n\n{f.exe_path}\n\n"
                "A different or modified file with the same name will NOT be trusted."):
            return
        if ctx.whitelist.add(f.wl_key, f.name, f.exe_path):
            for row, finding in list(findings_by_key.items()):
                if finding.wl_key == f.wl_key:
                    findings_by_key.pop(row)
            refresh_proc_table()
            refresh_whitelist_table()
            set_details("")
            append_ui_log(f"Whitelisted '{f.name}' by SHA-256 ({f.wl_key[:16]}...).")
        else:
            messagebox.showerror("Failed", f"Could not write the whitelist file:\n{ctx.whitelist.path}")

    def on_remove_whitelist_click() -> None:
        selected = whitelist_tree.selection()
        if not selected or ctx.whitelist is None:
            messagebox.showinfo("No Selection", "Select an entry in the Whitelist tab first.")
            return
        key = selected[0]
        name, path, _ = whitelist_tree.item(key, "values")
        if not messagebox.askyesno(
                "Remove from Whitelist",
                f"Remove {name} from the whitelist and scan for suspicious processes?\n\n{path}"):
            return
        if not ctx.whitelist.remove(key):
            messagebox.showerror("Failed", f"Could not write the whitelist file:\n{ctx.whitelist.path}")
            return
        refresh_whitelist_table()
        append_ui_log(f"Removed '{name}' from the whitelist. Rescanning running processes.")
        threading.Thread(target=perform_scan_worker, args=(False, False, (key, name)),
                         daemon=True).start()

    remove_whitelist_btn.configure(command=on_remove_whitelist_click)

    def on_open_dir_click() -> None:
        _, f = get_selected()
        if not f:
            messagebox.showinfo("Open Location", "Select a suspicious process first.")
            return
        path = f.file_path
        if not os.path.isfile(path):
            messagebox.showinfo("Unavailable", f"File is no longer accessible:\n{path}")
            return
        if IS_WINDOWS:
            try:
                select_file_in_explorer(path)
            except OSError as exc:
                messagebox.showerror("Open Location", f"Could not open File Explorer:\n{exc}")
        else:
            messagebox.showinfo("File Path", path)


    def on_export_click() -> None:
        if not findings_by_key and not persistence_state:
            messagebox.showinfo("Empty", "No findings to export.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")],
                                            initialfile="keylogger_report.json")
        if not dest:
            return
        payload = {
            "exported": datetime.datetime.now().isoformat(timespec="seconds"),
            "host": socket.gethostname(),
            "processes": [asdict(f) for f in findings_by_key.values()],
            "persistence": [asdict(p) for p in persistence_state],
        }
        try:
            Path(dest).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            append_ui_log(f"Exported {len(payload['processes'])} process and {len(payload['persistence'])} persistence finding(s) to {dest}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def on_close() -> None:
        monitor_stop_event.set()
        root.destroy()

    scan_btn.configure(command=on_scan_click)
    monitor_btn.configure(command=on_monitor_toggle)
    export_btn.configure(command=on_export_click)
    if IS_WINDOWS:
        startup_options.add_command(label="Open Suspicious Processes", command=show_suspicious_processes)
    kill_btn.configure(command=on_kill_click)
    delete_btn.configure(command=on_delete_click)
    whitelist_btn.configure(command=on_whitelist_click)
    open_dir_btn.configure(command=on_open_dir_click)
    root.protocol("WM_DELETE_WINDOW", on_close)

    # ── Queue Poller (main thread) ───────────────────────────────────────────
    def handle_scan_result(full: bool, total: int, new_findings: List[ProcessFinding]) -> None:
        nonlocal last_priorities
        kpi_vars["scanned"].set(str(total))
        if full:
            scan_btn.configure(state="normal")
        kpi_vars["status"].set("MONITORING" if monitoring_active else "IDLE")

        if ctx.whitelist is not None:
            new_findings = [f for f in new_findings if not ctx.whitelist.has(f.wl_key)]

        # The table always mirrors what is flagged *right now*: processes that exited drop out
        # (their history stays in the log tab and the JSONL file).
        previous = set(findings_by_key)
        findings_by_key.clear()
        fresh: List[ProcessFinding] = []
        for f in new_findings:
            key = proc_key(f.pid, f.start)
            findings_by_key[key] = f
            if key not in previous:
                fresh.append(f)
                append_finding_log(f, log_file)
                append_ui_log(f"[{f.severity}] PID {f.pid} ({f.name}) Score={f.score} — {'; '.join(f.reasons)}")
        if auto_monitor:
            notify_new_findings(fresh, sound=sound_var.get(), parent=root,
                                open_processes=show_suspicious_processes)

        if full:
            append_ui_log(f"Scan finished: {total} processes checked, {len(new_findings)} flagged.")
        elif fresh:
            show_banner(f"Detected {len(fresh)} new suspicious process(es)")
        refresh_proc_table()
        priorities = {proc_key(f.pid, f.start) for f in new_findings if f.severity in {"HIGH", "CRITICAL"}}
        if priorities - last_priorities:
            show_suspicious_processes()
        last_priorities = priorities

    def handle_persistence_result(persistence: List[PersistenceFinding]) -> None:
        nonlocal persistence_baseline
        persistence_state[:] = persistence
        new_items = [p for p in persistence if persistence_key(p) not in seen_persistence]
        seen_persistence.update(persistence_key(p) for p in persistence)
        refresh_persist_table()
        for p in new_items:
            append_ui_log(f"[PERSISTENCE] {p.location} / {p.name}: {p.reason} -> {p.command}")
        if new_items and persistence_baseline:
            show_banner(f"Detected {len(new_items)} new startup entries")
        persistence_baseline = True

    def show_whitelist_rescan_result(key: str, name: str) -> None:
        row = max(
            (row for row, finding in findings_by_key.items() if finding.wl_key == key),
            key=lambda row: findings_by_key[row].score, default=None,
        )
        if row is None:
            messagebox.showinfo(
                "Removed from Whitelist",
                f"{name} was removed. The scan found no running process that matched this entry "
                "and triggered an alert.",
            )
            return
        notebook.select(tab_procs)
        proc_tree.selection_set(row)
        proc_tree.focus(row)
        proc_tree.see(row)

    def poll_queue() -> None:
        try:
            while True:
                item = ui_queue.get_nowait()
                if item[0] == "scan_result":
                    _, full, total, findings, removed_entry = item
                    handle_scan_result(full, total, findings)
                    if removed_entry is not None:
                        show_whitelist_rescan_result(*removed_entry)
                elif item[0] == "whitelist_rescan_error":
                    messagebox.showwarning(
                        "Rescan Failed",
                        f"{item[1]} was removed from the whitelist. Use Scan Now to try again.",
                    )
                elif item[0] == "persistence_result":
                    handle_persistence_result(item[1])
                elif item[0] == "error":
                    _, full, msg = item
                    if full:
                        scan_btn.configure(state="normal")
                    kpi_vars["status"].set("MONITORING" if monitoring_active else "IDLE")
                    append_ui_log(f"Scan error: {msg}")
        except queue.Empty:
            pass
        root.after(150, poll_queue)

    append_ui_log("Keylogger Detector GUI initialized. Click 'Scan Now' or 'Start Monitor'.")
    if ctx.whitelist is not None and ctx.whitelist.ignored_legacy:
        append_ui_log(f"Ignored {ctx.whitelist.ignored_legacy} legacy name/path whitelist entries "
                      "(spoofable). Re-add them from the table to whitelist by SHA-256.")
    root.after(150, poll_queue)
    if alert_findings is not None:
        findings_by_key.update(
            (proc_key(f.pid, f.start), f) for f in alert_findings
            if ctx.whitelist is None or not ctx.whitelist.has(f.wl_key)
        )
        kpi_vars["status"].set("ALERT DETAILS")
        refresh_proc_table()
        root.after_idle(show_suspicious_processes)
    elif auto_monitor:
        on_monitor_toggle()
    else:
        root.after_idle(lambda: threading.Thread(
            target=perform_scan_worker, args=(False, False), daemon=True).start())
    root.mainloop()


# ============================================================================
# CLI Runner
# ============================================================================

def print_persistence(items: List[PersistenceFinding]) -> None:
    for p in items:
        print(f"    - [{p.location}] {p.name} -> {p.command} ({p.reason})")


def run_scan(log_file: Path, ctx: ScanContext, interactive: bool = False) -> List[ProcessFinding]:
    print(f"[*] Scanning running processes ({'psutil' if HAS_PSUTIL else 'native OS fallback'})...")
    total, findings = scan_processes(ctx)
    for finding in findings:
        trigger_alert(finding, log_file, sound=False)
    notify_new_findings(findings)

    persistence = scan_windows_persistence()
    if persistence:
        print("\n[!] Suspicious Startup / Persistence Entries Found:")
        print_persistence(persistence)

    if not findings and not persistence:
        print(f"[+] Clean scan: {total} processes checked, no suspicious keylogger activity found.")
    else:
        print(f"\n[*] Scan complete: {total} processes checked, {len(findings)} suspicious process(es) flagged.")
        print(f"[*] Alerts logged to: {log_file.resolve()}")

    if interactive and findings:
        for f in findings:
            try:
                ans = input(f"\n[?] PID {f.pid} ({f.name}): [d]elete / [k]ill / [w]hitelist / [s]kip (default s): ").strip().lower()
            except EOFError:
                break
            if ans == "d":
                try:
                    target, expected = resolve_delete_target(f)
                    confirm = input(f"Terminate PID {f.pid} and permanently delete {target}? [y/N] ")
                except (OSError, RuntimeError) as exc:
                    print(f"[-] {exc}")
                    continue
                except EOFError:
                    break
                if confirm.strip().lower() == "y":
                    _, deleted, message = delete_threat(f, target, expected)
                    print(f"[{'+' if deleted else '-'}] {message}")
            elif ans == "k":
                ok, msg = terminate_process(f.pid, f.start, f.exe_path)
                print(f"[{'+' if ok else '-'}] {msg}")
            elif ans == "w":
                if ctx.whitelist and f.wl_key and ctx.whitelist.add(f.wl_key, f.name, f.exe_path):
                    print(f"[+] Whitelisted by SHA-256 ({f.wl_key[:16]}...).")
                else:
                    print("[-] Could not whitelist (file unreadable or whitelist not writable).")
    return findings


def run_monitor(interval: float, log_file: Path, ctx: ScanContext) -> None:
    print(f"[*] Real-time Keylogger Monitor started (interval: {interval}s). Press Ctrl+C to stop.")
    alerted: Set[str] = set()
    seen_persistence: Set[Tuple[str, str, str]] = set()
    last_persistence = 0.0
    baseline_done = False

    try:
        while True:
            _, findings = scan_processes(ctx)
            fresh: List[ProcessFinding] = []
            for finding in findings:
                key = proc_key(finding.pid, finding.start)
                if key not in alerted:
                    alerted.add(key)
                    trigger_alert(finding, log_file, sound=False)
                    fresh.append(finding)
            notify_new_findings(fresh)
            now = time.time()
            if now - last_persistence >= PERSISTENCE_RESCAN_SECONDS:
                last_persistence = now
                current = scan_windows_persistence()
                new_items = [p for p in current if persistence_key(p) not in seen_persistence]
                seen_persistence.update(persistence_key(p) for p in current)
                if new_items:
                    print("\n[!] " + ("New " if baseline_done else "") + "Suspicious Startup / Persistence Entries:")
                    print_persistence(new_items)
                baseline_done = True

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Keylogger Detection Tool — Monitors processes, Win32 input APIs, scripts and persistence."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--gui", action="store_true", help="Launch the Tkinter graphical interface (default)")
    mode.add_argument("--alert-popup", action="store_true", help=argparse.SUPPRESS)
    mode.add_argument("--alert-viewer", action="store_true", help=argparse.SUPPRESS)
    mode.add_argument("--viewer", action="store_true", help="Open the GUI without starting another monitor")
    mode.add_argument("--scan", action="store_true", help="Run a one-time CLI deep scan")
    mode.add_argument("--monitor", action="store_true", help="Continuously monitor processes in CLI mode")
    parser.add_argument("--interval", type=float, default=3.0, help="Polling interval in seconds for --monitor (default: 3.0)")
    parser.add_argument("--interactive", action="store_true", help="Prompt to delete/kill/whitelist flagged processes after --scan")
    parser.add_argument("--log", type=Path, help="Output JSONL log path")
    parser.add_argument("--protected-storage", action="store_true",
                        help="Store logs and whitelist under ProgramData (requires Windows administrator)")
    parser.add_argument("--whitelist", type=Path, default=None,
                        help="Whitelist file (default: per-user config directory)")
    parser.add_argument("--trust-publisher", action="append", default=[], metavar="NAME",
                        help="Exact certificate CN/O to trust (repeatable). Valid signatures from it downgrade API findings")
    parser.add_argument("--no-signature-check", action="store_true",
                        help="Skip Authenticode verification (faster, but more false positives)")

    parser.add_argument("--behavior-trace", type=Path,
                        help="Read recent Windows keyboard API events from an external JSONL collector")
    mode.add_argument("--enable-sign-in", action="store_true", help="Start monitoring at Windows sign-in")
    mode.add_argument("--disable-sign-in", action="store_true", help="Remove the Windows sign-in entry")
    args = parser.parse_args()

    if args.enable_sign_in or args.disable_sign_in:
        try:
            configure_sign_in(args.enable_sign_in)
        except OSError as exc:
            parser.exit(1, f"Start at sign-in: {exc}\n")
        print("Start at sign-in enabled." if args.enable_sign_in else "Start at sign-in disabled.")
        return

    if args.alert_popup:
        payload = json.load(sys.stdin)
        if isinstance(payload, list):
            show_detection_popup(payload)
        else:
            show_detection_popup(payload["groups"], sound=payload["sound"],
                                 findings=payload.get("findings"))
        return

    for pub in args.trust_publisher:
        TRUSTED_PUBLISHERS.add(pub.strip().lower())

    data_dir = default_data_dir()
    default_log = Path("keylogger_alerts.jsonl")
    if args.protected_storage:
        try:
            data_dir = configure_protected_storage()
        except subprocess.CalledProcessError as exc:
            parser.exit(1, f"Protected storage: {exc.stderr.strip() or exc.stdout.strip() or exc}\n")
        except OSError as exc:
            parser.exit(1, f"Protected storage: {exc}\n")
        default_log = data_dir / "Logs" / "keylogger_alerts.jsonl"
    log_file = args.log or default_log
    whitelist = Whitelist(args.whitelist or (data_dir / "keylogger_whitelist.json"))
    ctx = ScanContext(whitelist=whitelist, check_signatures=not args.no_signature_check,
                      behavior_trace=args.behavior_trace)
    interval = max(1.0, args.interval)

    if args.alert_viewer:
        payload = json.load(sys.stdin)
        findings = [ProcessFinding(**item) for item in payload["findings"]]
        launch_gui(log_file, ctx, auto_monitor=False, alert_findings=findings)
    elif args.scan or args.monitor:
        print("=" * 64)
        print("  Keylogger Detection Tool v2 (Process, Script & Persistence Analyzer)")
        print(f"  Host: {socket.gethostname()} | OS: {sys.platform} | psutil: {HAS_PSUTIL}")
        print(f"  Whitelist: {whitelist.path} ({len(whitelist.entries)} entries)")
        print("=" * 64)
        if whitelist.ignored_legacy:
            print(f"[*] Ignored {whitelist.ignored_legacy} legacy name/path whitelist entries (spoofable).")
        if args.monitor:
            run_monitor(interval, log_file, ctx)
        else:
            run_scan(log_file, ctx, interactive=args.interactive)
    else:
        launch_gui(log_file, ctx, auto_monitor=not args.viewer)


if __name__ == "__main__":
    main()
