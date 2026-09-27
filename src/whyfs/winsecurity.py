"""Windows named-pipe transport and identity for the whyfs service API (ctypes, no pywin32).

Server: the pipe is created with an explicit DACL (SYSTEM and Administrators full control,
authenticated users read/write) and FILE_FLAG_FIRST_PIPE_INSTANCE for the first instance,
so no other process can own the name while the service runs.  The requester's user is taken
from the client's token by impersonation (after the first read, as Windows requires); the
requester is an administrator only if the token is elevated (Administrators enabled), so
an unelevated administrator sees only their own evidence, like any user.
Client: before sending anything, it checks that the pipe's server process runs as SYSTEM
(a pipe squatted by an ordinary user is refused).
"""
from __future__ import annotations

import ctypes
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)

INVALID = wintypes.HANDLE(-1).value
SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
SYSTEM_SID = "S-1-5-18"


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]


k32.CreateNamedPipeW.restype = wintypes.HANDLE
k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SECURITY_ATTRIBUTES)]
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                            wintypes.DWORD, wintypes.HANDLE]
k32.OpenProcess.restype = wintypes.HANDLE
k32.GetCurrentThread.restype = wintypes.HANDLE
_H, _P, _D = wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD
_LPD = ctypes.POINTER(wintypes.DWORD)
for fn, args in {
    (k32, "CloseHandle"): [_H], (k32, "LocalFree"): [_P],
    (k32, "ReadFile"): [_H, ctypes.c_char_p, _D, _LPD, _P], (k32, "WriteFile"): [_H, ctypes.c_char_p, _D, _LPD, _P],
    (k32, "ConnectNamedPipe"): [_H, _P], (k32, "DisconnectNamedPipe"): [_H], (k32, "FlushFileBuffers"): [_H],
    (k32, "GetNamedPipeClientProcessId"): [_H, ctypes.POINTER(wintypes.ULONG)],
    (k32, "GetNamedPipeServerProcessId"): [_H, ctypes.POINTER(wintypes.ULONG)],
    (k32, "OpenProcess"): [_D, wintypes.BOOL, _D], (k32, "WaitNamedPipeW"): [wintypes.LPCWSTR, _D],
    (k32, "QueryFullProcessImageNameW"): [_H, _D, wintypes.LPWSTR, _LPD],
    (adv, "ConvertSidToStringSidW"): [_P, ctypes.POINTER(wintypes.LPWSTR)],
    (adv, "ConvertStringSidToSidW"): [wintypes.LPCWSTR, ctypes.POINTER(_P)],
    (adv, "OpenProcessToken"): [_H, _D, ctypes.POINTER(_H)],
    (adv, "OpenThreadToken"): [_H, _D, wintypes.BOOL, ctypes.POINTER(_H)],
    (adv, "GetTokenInformation"): [_H, ctypes.c_int, ctypes.c_char_p, _D, _LPD],
    (adv, "DuplicateToken"): [_H, ctypes.c_int, ctypes.POINTER(_H)],
    (adv, "CheckTokenMembership"): [_H, _P, ctypes.POINTER(wintypes.BOOL)],
    (adv, "ImpersonateNamedPipeClient"): [_H], (adv, "RevertToSelf"): [],
    (adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW"): [wintypes.LPCWSTR, _D, ctypes.POINTER(_P), _P],
    (adv, "GetSecurityDescriptorDacl"): [_P, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(_P), ctypes.POINTER(wintypes.BOOL)],
    (adv, "SetNamedSecurityInfoW"): [wintypes.LPWSTR, ctypes.c_int, _D, _P, _P, _P, _P],
}.items():
    getattr(fn[0], fn[1]).argtypes = args


def _check(ok, what):
    if not ok:
        raise OSError(ctypes.get_last_error(), f"{what} failed")


def _sid_string(psid) -> str:
    s = wintypes.LPWSTR()
    _check(adv.ConvertSidToStringSidW(psid, ctypes.byref(s)), "ConvertSidToStringSid")
    try:
        return s.value
    finally:
        k32.LocalFree(s)


def _token_user(tok) -> str:
    n = wintypes.DWORD()
    adv.GetTokenInformation(tok, 1, None, 0, ctypes.byref(n))  # TokenUser
    buf = ctypes.create_string_buffer(n.value)
    _check(adv.GetTokenInformation(tok, 1, buf, n, ctypes.byref(n)), "GetTokenInformation")
    psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
    return _sid_string(psid)


def _token_is_admin(tok) -> bool:
    sid = ctypes.c_void_p()
    _check(adv.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid)), "ConvertStringSidToSid")
    try:
        # CheckTokenMembership wants an impersonation token: duplicate the primary/impersonation token
        dup = wintypes.HANDLE()
        _check(adv.DuplicateToken(tok, 2, ctypes.byref(dup)), "DuplicateToken")  # SecurityImpersonation
        try:
            member = wintypes.BOOL()
            _check(adv.CheckTokenMembership(dup, sid, ctypes.byref(member)), "CheckTokenMembership")
            return bool(member.value)
        finally:
            k32.CloseHandle(dup)
    finally:
        k32.LocalFree(sid)


def process_sid(pid: int) -> str | None:
    """User SID of a live process (the service runs as SYSTEM and may query any)."""
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return None
    try:
        tok = wintypes.HANDLE()
        if not adv.OpenProcessToken(h, 8, ctypes.byref(tok)):  # TOKEN_QUERY
            return None
        try:
            return _token_user(tok)
        finally:
            k32.CloseHandle(tok)
    finally:
        k32.CloseHandle(h)


def process_image(pid: int) -> str | None:
    h = k32.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = wintypes.DWORD(1024)
        return buf.value if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else None
    finally:
        k32.CloseHandle(h)


def trusted_server(pid: int) -> bool:
    """The pipe's server is the whyfs service: it runs as SYSTEM, or (when an unprivileged
    client cannot read a SYSTEM token) its image lies in the protected install directory.
    A server running as the client's own user, or any other readable non-SYSTEM user, is a
    squatter."""
    import os
    owner = process_sid(pid)
    if owner == SYSTEM_SID:
        return True
    if owner is not None:
        return False
    img = (process_image(pid) or "").lower()
    inst = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "whyfs").lower() + "\\"
    return img.startswith(inst)


# ---------------------------------------------------------------- server side
def pipe_create(name: str, first: bool = False):
    sd = ctypes.c_void_p()
    _check(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL, 1, ctypes.byref(sd), None), "SDDL")
    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
    mode = 0x3 | (0x00080000 if first else 0)  # PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
    h = k32.CreateNamedPipeW(name, mode, 0, 255, 65536, 65536, 0, ctypes.byref(sa))
    k32.LocalFree(sd)
    if h == INVALID:
        raise OSError(ctypes.get_last_error(), f"CreateNamedPipe {name} failed (another process owns the name?)")
    return h


def pipe_accept(h) -> bool:
    if k32.ConnectNamedPipe(h, None):
        return True
    return ctypes.get_last_error() == 535  # ERROR_PIPE_CONNECTED


def pipe_read(h, n: int = 65536) -> bytes:
    buf = ctypes.create_string_buffer(n)
    got = wintypes.DWORD()
    if not k32.ReadFile(h, buf, n, ctypes.byref(got), None):
        err = ctypes.get_last_error()
        if err in (109, 232):  # broken pipe / no data
            return b""
        if err != 234:  # ERROR_MORE_DATA
            raise OSError(err, "ReadFile failed")
    return buf.raw[:got.value]


def pipe_write(h, data: bytes) -> None:
    off = 0
    while off < len(data):
        n = wintypes.DWORD()
        _check(k32.WriteFile(h, data[off:], len(data) - off, ctypes.byref(n), None), "WriteFile")
        off += n.value
    k32.FlushFileBuffers(h)


def pipe_close(h) -> None:
    k32.DisconnectNamedPipe(h)
    k32.CloseHandle(h)


def pipe_client_context(h) -> dict:
    pid = wintypes.ULONG()
    k32.GetNamedPipeClientProcessId(h, ctypes.byref(pid))
    _check(adv.ImpersonateNamedPipeClient(h), "ImpersonateNamedPipeClient")
    try:
        tok = wintypes.HANDLE()
        _check(adv.OpenThreadToken(k32.GetCurrentThread(), 0x8 | 0x2, True, ctypes.byref(tok)), "OpenThreadToken")  # QUERY | DUPLICATE
        try:
            user = _token_user(tok)
            admin = _token_is_admin(tok)
        finally:
            k32.CloseHandle(tok)
    finally:
        adv.RevertToSelf()
    return {"user": user, "admin": admin, "pid": pid.value}


# ---------------------------------------------------------------- client side
def pipe_client_call(name: str, request: bytes, timeout: float = 30.0) -> bytes:
    from .api import ServiceUnavailable
    deadline = time.monotonic() + timeout
    while True:
        h = k32.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)  # GENERIC_READ|WRITE, OPEN_EXISTING
        if h != INVALID:
            break
        err = ctypes.get_last_error()
        if err == 231 and time.monotonic() < deadline:  # ERROR_PIPE_BUSY
            k32.WaitNamedPipeW(name, 1000)
            continue
        raise ServiceUnavailable(f"the whyfs service is not running ({name}: error {err})")
    try:
        spid = wintypes.ULONG()
        _check(k32.GetNamedPipeServerProcessId(h, ctypes.byref(spid)), "GetNamedPipeServerProcessId")
        if not trusted_server(spid.value):
            raise ServiceUnavailable(f"refusing {name}: its server (pid {spid.value}) is not the whyfs service")
        pipe_write(h, request)
        out = b""
        while not out.endswith(b"\n"):
            chunk = pipe_read(h)
            if not chunk:
                break
            out += chunk
        return out
    finally:
        k32.CloseHandle(h)


def protect_dir(path: str, sddl: str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") -> None:
    """Give ``path`` (and, by inheritance, everything in it) a protected DACL: SYSTEM and
    Administrators only.  The machine store holds every user's evidence."""
    sd = ctypes.c_void_p()
    _check(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None), "SDDL")
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = ctypes.c_void_p()
        _check(adv.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)),
               "GetSecurityDescriptorDacl")
        # SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        rc = adv.SetNamedSecurityInfoW(ctypes.c_wchar_p(path), 1, 0x4 | 0x80000000, None, None, dacl, None)
        if rc != 0:
            raise OSError(rc, f"SetNamedSecurityInfo {path} failed")
    finally:
        k32.LocalFree(sd)
