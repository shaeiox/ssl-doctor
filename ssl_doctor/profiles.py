"""Remembered SSH servers: named, non-secret connection profiles.

A profile is what the operator would otherwise type again -- host, port, user,
auth method, key path, TLS target -- plus bookkeeping (whether a password is
saved in the OS vault, the host-key fingerprints it was saved against, when it
was used). It never holds a password, key, passphrase or raw ssh option; those
cannot be expressed in the schema at all (ADR-001).

The file is untrusted input: anyone who can write it could otherwise steer the
ssh command line, so every field is validated against an allowlist on load and
values that ssh would read as options (a leading "-") are rejected. Writes are
atomic and owner-only.
"""

from __future__ import annotations

import difflib
import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

SCHEMA = 1
FILE_NAME = "profiles.json"

_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HOST = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_AUTH = ("password", "key")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_time(value: str) -> datetime:
    stamp = datetime.fromisoformat(value)
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def _text(value, label: str, limit: int, pattern=None, allow_empty=False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label}: not text")
    if not value:
        if allow_empty:
            return value
        raise ValueError(f"{label}: empty")
    if len(value) > limit or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError(f"{label}: invalid characters or too long")
    if value.startswith("-"):                    # ssh would read it as an option
        raise ValueError(f"{label}: may not start with '-'")
    if pattern is not None and not pattern.match(value):
        raise ValueError(f"{label}: invalid value")
    return value


def _port(value, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"{label}: not a port")
    return value


def _stamp(value, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label}: not a timestamp")
    try:
        parse_time(value)
    except ValueError:
        raise ValueError(f"{label}: not a timestamp") from None
    return value


@dataclass
class Profile:
    name: str
    host: str
    port: int = 22
    username: str = ""
    auth: str = "key"
    key_path: str = ""
    tls_host: str = ""
    tls_port: int = 443
    password_saved: bool = False
    hostkey_fingerprints: List[str] = field(default_factory=list)
    created: str = field(default_factory=now_iso)
    last_used: str = field(default_factory=now_iso)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _text(self.name, "name", 64, _NAME)
        _text(self.host, "host", 253, _HOST)
        _port(self.port, "port")
        _text(self.username, "username", 128)
        if self.auth not in _AUTH:
            raise ValueError("auth: must be 'password' or 'key'")
        _text(self.key_path, "key_path", 4096, allow_empty=True)
        _text(self.tls_host, "tls_host", 253, _HOST, allow_empty=True)
        _port(self.tls_port, "tls_port")
        if not isinstance(self.password_saved, bool):
            raise ValueError("password_saved: not a boolean")
        if (not isinstance(self.hostkey_fingerprints, list)
                or len(self.hostkey_fingerprints) > 8
                or not all(isinstance(fp, str) and _FINGERPRINT.match(fp)
                           for fp in self.hostkey_fingerprints)):
            raise ValueError("hostkey_fingerprints: invalid")
        _stamp(self.created, "created")
        _stamp(self.last_used, "last_used")

    @property
    def endpoint(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "Profile":
        """Build from untrusted data: unknown keys are dropped, values validated."""
        if not isinstance(data, dict):
            raise ValueError("profile: not an object")
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def default_name(host: str, taken) -> str:
    """The short host label (`files` for files.example.com), else the host."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        candidates = [host]
    except ValueError:
        candidates = [host.split(".")[0], host]
    for candidate in candidates:
        candidate = re.sub(r"[^A-Za-z0-9._-]", "-", candidate)[:64].lstrip("-") or "server"
        if candidate not in taken:
            return candidate
    index = 2
    while f"{candidates[0]}-{index}" in taken:
        index += 1
    return f"{candidates[0]}-{index}"


class ProfileStore:
    """`profiles.json` in the private state directory."""

    def __init__(self, path: Optional[str] = None,
                 warn: Optional[Callable[[str], None]] = None) -> None:
        if path is None:
            from .server import _ensure_state_dir
            path = os.path.join(_ensure_state_dir(), FILE_NAME)
        self.path = path
        self.warn = warn or (lambda message: None)
        self.read_only = False                 # set when the file could not be parsed
        self._profiles: Dict[str, Profile] = {}

    # -- reading ---------------------------------------------------------
    def load(self) -> "ProfileStore":
        self._profiles, self.read_only = self._read(report=True)
        return self

    def _read(self, report: bool):
        try:
            with open(self.path, encoding="utf-8") as fh:
                raw = fh.read()
        except FileNotFoundError:
            return {}, False
        except OSError as exc:
            if report:
                self.warn(f"saved servers could not be read: {exc.strerror or exc}")
            return {}, True
        try:
            document = json.loads(raw)
            if not isinstance(document, dict) or not isinstance(document.get("profiles"), list):
                raise ValueError("not a profiles document")
        except ValueError:
            if report:
                self.warn(f"saved servers could not be read: {self.path} is not a valid "
                          "profiles file (left untouched)")
            return {}, True
        found: Dict[str, Profile] = {}
        for entry in document["profiles"]:
            try:
                profile = Profile.from_dict(entry)
            except (TypeError, ValueError) as exc:
                if report:
                    label = entry.get("name") if isinstance(entry, dict) else "?"
                    self.warn(f"saved server {label!s:.64} skipped: {exc}")
                continue
            found[profile.name] = profile
        return found, False

    def all(self) -> List[Profile]:
        return sorted(self._profiles.values(), key=lambda p: p.name)

    def get(self, name: str) -> Optional[Profile]:
        return self._profiles.get(name)

    def closest(self, name: str, limit: int = 3) -> List[str]:
        return difflib.get_close_matches(name, list(self._profiles), n=limit, cutoff=0.5)

    def recent(self, limit: int = 5) -> List[Profile]:
        return sorted(self._profiles.values(), key=lambda p: parse_time(p.last_used),
                      reverse=True)[:limit]

    def match_domain(self, domain: str) -> Optional[Profile]:
        """The profile whose TLS target, else SSH host, is `domain` (most recent)."""
        domain = domain.strip().lower()
        for attr in ("tls_host", "host"):
            hits = [p for p in self.recent(len(self._profiles))
                    if getattr(p, attr).lower() == domain]
            if hits:
                return hits[0]
        return None

    def for_host(self, host: str) -> Optional[Profile]:
        host = host.strip().lower()
        hits = [p for p in self.recent(len(self._profiles)) if p.host.lower() == host]
        return hits[0] if hits else None

    def expire(self, vault, now: Optional[datetime] = None) -> List[str]:
        """Delete saved passwords unused for the expiry period; returns the names.

        Only while the vault is reachable: with the vault locked or absent the
        entry could not be deleted, so the marker stays for a later session.
        """
        from .vault import VaultError, expired, target_for
        if not vault.available()[0]:
            return []
        gone = []
        for profile in self.all():
            if profile.password_saved and expired(parse_time(profile.last_used), now):
                try:
                    vault.delete(target_for(profile))
                except VaultError as exc:
                    self.warn(f"saved password for {profile.name} could not be expired: {exc}")
                    continue
                profile.password_saved = False
                self.save(profile)
                gone.append(profile.name)
        return gone

    # -- writing ---------------------------------------------------------
    def save(self, profile: Profile) -> None:
        profile.validate()
        self._update(lambda current: current.__setitem__(profile.name, profile))

    def forget(self, name: str) -> bool:
        if name not in self._profiles and name not in self._read(report=False)[0]:
            return False
        self._update(lambda current: current.pop(name, None))
        return True

    def _update(self, change) -> None:
        # read-modify-write, so another session's new profiles are kept
        current, corrupt = self._read(report=False)
        if corrupt and os.path.exists(self.path):
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            os.replace(self.path, f"{self.path}.bad-{stamp}")
            current = {}
        change(current)
        self._write(current)
        self._profiles, self.read_only = current, False

    def _write(self, current: Dict[str, Profile]) -> None:
        text = json.dumps({"schema": SCHEMA,
                           "profiles": [current[k].to_dict() for k in sorted(current)]},
                          indent=2) + "\n"
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            if os.name != "nt":
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
