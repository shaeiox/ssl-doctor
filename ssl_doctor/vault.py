"""Saved SSH passwords, kept only in the operating system's credential vault.

SSL Doctor never writes a password to a file of its own (ADR-001). A saved
password lives in Windows Credential Manager or the Linux Secret Service, is
tagged with the host-key fingerprints it was saved against, and is released
only when one of those fingerprints is presented again -- so a hijacked name or
an edited profile finds nothing. Where no vault exists, :class:`NullVault`
stores nothing and the operator is asked every time.

Secrets cross process boundaries only through stdin/stdout or an in-process
API, never a command line.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Sequence, Tuple

TARGET_PREFIX = "ssl-doctor:ssh:"
TOOL_TIMEOUT = 10.0
EXPIRY_DAYS = 90


class VaultError(Exception):
    """The vault refused or failed; the message never contains the secret."""


def target_name(username: str, host: str, port: int) -> str:
    return f"{TARGET_PREFIX}{username}@{host}:{port}"


def target_for(profile) -> str:
    return target_name(profile.username, profile.host, profile.port)


class SecretVault:
    """`available`, `get`, `put`, `delete` -- one entry per target."""

    name = "credential vault"

    def available(self) -> Tuple[bool, str]:
        return True, ""

    def get(self, target: str, fingerprints: Sequence[str]) -> Optional[str]:
        raise NotImplementedError

    def put(self, target: str, secret: str, fingerprints: Sequence[str]) -> None:
        raise NotImplementedError

    def delete(self, target: str) -> None:
        raise NotImplementedError


class NullVault(SecretVault):
    """No vault on this machine (or remembering is off): stores nothing."""

    name = "no credential vault"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def available(self) -> Tuple[bool, str]:
        return False, self.reason

    def get(self, target, fingerprints):
        return None

    def put(self, target, secret, fingerprints):
        raise VaultError(f"passwords cannot be saved: {self.reason}")

    def delete(self, target):
        return None


class MemoryVault(SecretVault):
    """An in-process vault for tests and embedding; forgets everything on exit."""

    name = "memory"

    def __init__(self) -> None:
        self.items: Dict[str, Tuple[str, Tuple[str, ...]]] = {}

    def get(self, target, fingerprints):
        item = self.items.get(target)
        if item and set(item[1]) & set(fingerprints):
            return item[0]
        return None

    def put(self, target, secret, fingerprints):
        self.items[target] = (secret, tuple(fingerprints))

    def delete(self, target):
        self.items.pop(target, None)


# ------------------------------------------------------------- Windows

_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2       # per user, this machine; not roaming
_CRED_MAX_BLOB = 5 * 512              # CRED_MAX_CREDENTIAL_BLOB_SIZE
_ERROR_NOT_FOUND = 1168


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [("Flags", ctypes.c_uint32), ("Type", ctypes.c_uint32),
                ("TargetName", ctypes.c_wchar_p), ("Comment", ctypes.c_wchar_p),
                ("LastWritten", _FILETIME), ("CredentialBlobSize", ctypes.c_uint32),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", ctypes.c_uint32), ("AttributeCount", ctypes.c_uint32),
                ("Attributes", ctypes.c_void_p), ("TargetAlias", ctypes.c_wchar_p),
                ("UserName", ctypes.c_wchar_p)]


class WindowsCredentialVault(SecretVault):
    """Windows Credential Manager (DPAPI-protected, per user) through advapi32."""

    name = "Windows Credential Manager"

    def __init__(self, advapi32=None) -> None:
        self._api = advapi32

    def _advapi(self):
        if self._api is None:
            api = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
            api.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), ctypes.c_uint32]
            api.CredReadW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                      ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))]
            api.CredDeleteW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
            api.CredFree.argtypes = [ctypes.c_void_p]
            self._api = api
        return self._api

    def available(self) -> Tuple[bool, str]:
        try:
            self._advapi()
        except (AttributeError, OSError) as exc:
            return False, f"Windows Credential Manager is unavailable ({exc})"
        return True, ""

    def _last_error(self) -> int:
        return ctypes.get_last_error()  # type: ignore[attr-defined]

    def _error(self, action: str) -> VaultError:
        return VaultError(f"Windows Credential Manager could not {action} "
                          f"(error {self._last_error()})")

    def put(self, target, secret, fingerprints):
        blob = secret.encode("utf-8")
        if len(blob) > _CRED_MAX_BLOB:
            raise VaultError("the password is too long for Windows Credential Manager")
        buffer = (ctypes.c_ubyte * max(1, len(blob))).from_buffer_copy(blob or b"\0")
        username = target[len(TARGET_PREFIX):].rsplit("@", 1)[0] if target.startswith(
            TARGET_PREFIX) else ""
        cred = _CREDENTIALW(Flags=0, Type=_CRED_TYPE_GENERIC, TargetName=target,
                            Comment="hostkey=" + ",".join(fingerprints),
                            CredentialBlobSize=len(blob),
                            CredentialBlob=ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
                            Persist=_CRED_PERSIST_LOCAL_MACHINE, AttributeCount=0,
                            Attributes=None, TargetAlias=None, UserName=username)
        try:
            if not self._advapi().CredWriteW(ctypes.byref(cred), 0):
                raise self._error("save the password")
        finally:
            ctypes.memset(buffer, 0, ctypes.sizeof(buffer))

    def get(self, target, fingerprints):
        found = ctypes.POINTER(_CREDENTIALW)()
        api = self._advapi()
        if not api.CredReadW(target, _CRED_TYPE_GENERIC, 0, ctypes.byref(found)):
            if self._last_error() == _ERROR_NOT_FOUND:
                return None
            raise self._error("read the saved password")
        try:
            cred = found.contents
            saved = (cred.Comment or "").partition("hostkey=")[2].split(",")
            if not set(fp for fp in saved if fp) & set(fingerprints):
                return None
            size = cred.CredentialBlobSize
            secret = ctypes.string_at(cred.CredentialBlob, size).decode("utf-8")
            ctypes.memset(cred.CredentialBlob, 0, size)
            return secret
        finally:
            api.CredFree(found)

    def delete(self, target):
        if not self._advapi().CredDeleteW(target, _CRED_TYPE_GENERIC, 0):
            if self._last_error() != _ERROR_NOT_FOUND:
                raise self._error("delete the saved password")


# --------------------------------------------------------- Secret Service

class SecretServiceVault(SecretVault):
    """The freedesktop Secret Service (GNOME Keyring, KWallet) via `secret-tool`.

    One item per saved host-key fingerprint, all sharing the target attribute:
    the lookup includes the presented fingerprint, so the keyring itself
    enforces the host-key binding.
    """

    name = "Secret Service"

    def __init__(self, env: Optional[Dict[str, str]] = None,
                 run: Callable = subprocess.run) -> None:
        self.env = dict(os.environ if env is None else env)
        self._run = run

    def _tool(self) -> Optional[str]:
        return shutil.which("secret-tool", path=self.env.get("PATH"))

    def _call(self, args: List[str], secret: Optional[str] = None):
        tool = self._tool()
        if not tool:
            raise VaultError("secret-tool is not installed")
        try:
            return self._run([tool, *args], input=secret if secret is not None else "",
                             capture_output=True, text=True, timeout=TOOL_TIMEOUT,
                             env=self.env, shell=False)
        except subprocess.TimeoutExpired:
            raise VaultError("the Secret Service did not answer (locked keyring?)") from None
        except OSError as exc:
            raise VaultError(f"secret-tool could not run: {exc.strerror or exc}") from None

    @staticmethod
    def _summary(proc) -> str:
        line = (proc.stderr or "").strip().splitlines()
        return line[0][:200] if line else f"exit status {proc.returncode}"

    def available(self) -> Tuple[bool, str]:
        if not self._tool():
            return False, "secret-tool is not installed (package libsecret-tools)"
        if not self.env.get("DBUS_SESSION_BUS_ADDRESS"):
            return False, "no desktop session bus, so no Secret Service is reachable"
        try:
            proc = self._call(["search", "application", "ssl-doctor-probe", "probe", "1"])
        except VaultError as exc:
            return False, str(exc)
        if (proc.stderr or "").strip():
            return False, f"the Secret Service is not reachable: {self._summary(proc)}"
        return True, ""

    def put(self, target, secret, fingerprints):
        if not fingerprints:
            raise VaultError("no host-key fingerprint to bind the password to")
        self.delete(target)
        for fp in fingerprints:
            proc = self._call(["store", "--label", f"SSL Doctor: {target[len(TARGET_PREFIX):]}",
                               "application", "ssl-doctor", "kind", "ssh-password",
                               "target", target, "hostkey", fp], secret=secret)
            if proc.returncode != 0:
                raise VaultError(f"the Secret Service refused the password: "
                                 f"{self._summary(proc)}")

    def get(self, target, fingerprints):
        for fp in fingerprints:
            proc = self._call(["lookup", "application", "ssl-doctor", "target", target,
                               "hostkey", fp])
            if proc.returncode == 0 and proc.stdout:
                return proc.stdout[:-1] if proc.stdout.endswith("\n") else proc.stdout
            if proc.returncode != 0 and (proc.stderr or "").strip():
                raise VaultError(f"the Secret Service could not be read: {self._summary(proc)}")
        return None

    def delete(self, target):
        proc = self._call(["clear", "application", "ssl-doctor", "target", target])
        if proc.returncode != 0 and (proc.stderr or "").strip():
            raise VaultError(f"the Secret Service could not delete the password: "
                             f"{self._summary(proc)}")


# --------------------------------------------------------------- selection

def open_vault(enabled: bool = True, platform: Optional[str] = None,
               env: Optional[Dict[str, str]] = None,
               secret_service: Callable[[Dict[str, str]], SecretVault] = SecretServiceVault
               ) -> SecretVault:
    """The vault for this session, or a NullVault that says why there is none."""
    if not enabled:
        return NullVault("remembering passwords is turned off for this session")
    platform = sys.platform if platform is None else platform
    env = dict(os.environ if env is None else env)
    if platform.startswith("win"):
        candidate = WindowsCredentialVault()
        if os.name == "nt":
            ok, reason = candidate.available()
            if not ok:
                return NullVault(reason)
        return candidate
    if platform == "darwin":
        return NullVault("the macOS Keychain is not supported yet")
    candidate = secret_service(env)
    ok, reason = candidate.available()
    return candidate if ok else NullVault(reason)


def expired(last_used: datetime, now: Optional[datetime] = None,
            days: int = EXPIRY_DAYS) -> bool:
    now = now or datetime.now(timezone.utc)
    return now - last_used > timedelta(days=days)
