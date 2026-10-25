"""Credential vault backends: one contract, three stores, no secret in argv.

Covers openspec change `remembered-servers`, capability `credential-vault`:
passwords live only in the OS vault, are released only for a matching host-key
fingerprint, never cross a command line, and expire when unused.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from ssl_doctor import profiles, vault

FP_A = "SHA256:" + "A" * 43
FP_B = "SHA256:" + "B" * 43
SECRET = "p@ss w%rd&|^!\"é"


class Contract:
    """Behaviour every working backend must have."""

    def make(self):
        raise NotImplementedError

    def target(self):
        return vault.target_name("eleven", "files.example.com", 22)

    def setUp(self):
        super().setUp()
        self.vault = self.make()
        self.addCleanup(self.vault.delete, self.target())

    def test_put_then_get(self):
        self.vault.put(self.target(), SECRET, [FP_A])
        self.assertEqual(self.vault.get(self.target(), [FP_A]), SECRET)

    def test_a_different_host_key_releases_nothing(self):
        self.vault.put(self.target(), SECRET, [FP_A])
        self.assertIsNone(self.vault.get(self.target(), [FP_B]))
        self.assertIsNone(self.vault.get(self.target(), []))

    def test_any_saved_fingerprint_matches(self):
        self.vault.put(self.target(), SECRET, [FP_A, FP_B])
        self.assertEqual(self.vault.get(self.target(), [FP_B]), SECRET)

    def test_missing_entry(self):
        self.assertIsNone(self.vault.get(self.target(), [FP_A]))

    def test_delete(self):
        self.vault.put(self.target(), SECRET, [FP_A])
        self.vault.delete(self.target())
        self.assertIsNone(self.vault.get(self.target(), [FP_A]))
        self.vault.delete(self.target())                 # deleting twice is fine

    def test_put_replaces_the_previous_secret(self):
        self.vault.put(self.target(), "old", [FP_A])
        self.vault.put(self.target(), "new", [FP_B])
        self.assertIsNone(self.vault.get(self.target(), [FP_A]))
        self.assertEqual(self.vault.get(self.target(), [FP_B]), "new")

    def test_it_is_available(self):
        ok, reason = self.vault.available()
        self.assertTrue(ok, reason)


class MemoryVaultContract(Contract, unittest.TestCase):
    def make(self):
        return vault.MemoryVault()


class NullVaultBehaviour(unittest.TestCase):

    def test_never_stores_and_says_why(self):
        null = vault.NullVault("no Secret Service on this machine")
        self.assertEqual(null.available(), (False, "no Secret Service on this machine"))
        with self.assertRaises(vault.VaultError):
            null.put("t", SECRET, [FP_A])
        self.assertIsNone(null.get("t", [FP_A]))
        null.delete("t")


class TargetNames(unittest.TestCase):

    def test_target_name(self):
        self.assertEqual(vault.target_name("eleven", "files.example.com", 2222),
                         "ssl-doctor:ssh:eleven@files.example.com:2222")


FAKE_SECRET_TOOL = textwrap.dedent('''\
    #!{python}
    """A stand-in for libsecret's secret-tool that keeps items in a JSON file."""
    import json, os, sys
    db, log = os.environ["FAKE_SECRET_DB"], os.environ["FAKE_SECRET_ARGV_LOG"]
    with open(log, "a") as fh:
        fh.write(json.dumps(sys.argv[1:]) + "\\n")
    items = json.load(open(db)) if os.path.exists(db) else []
    cmd, args = sys.argv[1], sys.argv[2:]
    def attrs(pairs):
        return dict(zip(pairs[0::2], pairs[1::2]))
    if cmd == "store":
        label = args[args.index("--label") + 1]
        rest = args[:args.index("--label")] + args[args.index("--label") + 2:]
        items.append({{"attrs": attrs(rest), "secret": sys.stdin.read(), "label": label}})
    elif cmd == "lookup":
        want = attrs(args)
        hits = [i for i in items if all(i["attrs"].get(k) == v for k, v in want.items())]
        if not hits:
            sys.exit(1)
        sys.stdout.write(hits[-1]["secret"])
    elif cmd == "clear":
        want = attrs(args)
        items = [i for i in items if not all(i["attrs"].get(k) == v for k, v in want.items())]
    elif cmd == "search":
        pass
    json.dump(items, open(db, "w"))
''')


@unittest.skipIf(os.name == "nt", "the fake secret-tool is a POSIX script")
class SecretServiceContract(Contract, unittest.TestCase):

    def make(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        tool = os.path.join(self.dir, "secret-tool")
        with open(tool, "w") as fh:
            fh.write(FAKE_SECRET_TOOL.format(python=sys.executable))
        os.chmod(tool, 0o700)
        self.argv_log = os.path.join(self.dir, "argv.log")
        env = dict(os.environ, PATH=self.dir + os.pathsep + os.environ.get("PATH", ""),
                   DBUS_SESSION_BUS_ADDRESS="unix:path=/fake",
                   FAKE_SECRET_DB=os.path.join(self.dir, "db.json"),
                   FAKE_SECRET_ARGV_LOG=self.argv_log)
        return vault.SecretServiceVault(env=env)

    def test_the_secret_never_appears_in_argv(self):
        self.vault.put(self.target(), SECRET, [FP_A, FP_B])
        self.vault.get(self.target(), [FP_B])
        self.vault.delete(self.target())
        with open(self.argv_log) as fh:
            calls = [json.loads(line) for line in fh]
        self.assertTrue(calls)
        for argv in calls:
            self.assertFalse(any("p@ss" in arg for arg in argv), argv)

    def test_unavailable_without_a_session_bus(self):
        env = dict(self.vault.env)
        env.pop("DBUS_SESSION_BUS_ADDRESS")
        ok, reason = vault.SecretServiceVault(env=env).available()
        self.assertFalse(ok)
        self.assertIn("session", reason)

    def test_unavailable_without_secret_tool(self):
        ok, reason = vault.SecretServiceVault(env={"PATH": self.dir + "-missing",
                                                   "DBUS_SESSION_BUS_ADDRESS": "x"}).available()
        self.assertFalse(ok)
        self.assertIn("secret-tool", reason)


@unittest.skipUnless(shutil.which("secret-tool") and os.environ.get("DBUS_SESSION_BUS_ADDRESS")
                     and os.environ.get("SSL_DOCTOR_TEST_SECRET_SERVICE") == "1",
                     "real Secret Service: set SSL_DOCTOR_TEST_SECRET_SERVICE=1 on a desktop")
class RealSecretServiceContract(Contract, unittest.TestCase):
    def make(self):
        return vault.SecretServiceVault()

    def target(self):
        return f"ssl-doctor-test:{self.id_}:eleven@files.example.com:22"

    def setUp(self):
        self.id_ = uuid.uuid4().hex
        super().setUp()


@unittest.skipUnless(os.name == "nt", "Windows Credential Manager")
class WindowsCredentialContract(Contract, unittest.TestCase):
    def make(self):
        return vault.WindowsCredentialVault()

    def target(self):
        return f"ssl-doctor-test:{self.id_}:eleven@files.example.com:22"

    def setUp(self):
        self.id_ = uuid.uuid4().hex
        super().setUp()

    def test_an_oversized_secret_is_refused(self):
        with self.assertRaises(vault.VaultError):
            self.vault.put(self.target(), "x" * 3000, [FP_A])


class FakeAdvapi32:
    """advapi32's Cred* calls over the real CREDENTIALW structures (any OS)."""

    def __init__(self):
        self.store, self.error, self.freed, self.live = {}, 0, 0, []

    def CredWriteW(self, cred_ref, flags):
        cred = cred_ref._obj
        assert cred.Type == vault._CRED_TYPE_GENERIC
        assert cred.Persist == vault._CRED_PERSIST_LOCAL_MACHINE
        blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
        self.store[cred.TargetName] = (blob, cred.Comment, cred.UserName)
        return 1

    def CredReadW(self, target, kind, flags, out_ref):
        if target not in self.store:
            self.error = vault._ERROR_NOT_FOUND
            return 0
        blob, comment, user = self.store[target]
        buffer = (ctypes.c_ubyte * max(1, len(blob))).from_buffer_copy(blob or b"\0")
        cred = vault._CREDENTIALW(Type=kind, TargetName=target, Comment=comment,
                                  CredentialBlobSize=len(blob), UserName=user,
                                  CredentialBlob=ctypes.cast(buffer,
                                                             ctypes.POINTER(ctypes.c_ubyte)))
        self.live.append((buffer, cred))
        out_ref._obj.contents = cred
        return 1

    def CredDeleteW(self, target, kind, flags):
        if self.store.pop(target, None) is None:
            self.error = vault._ERROR_NOT_FOUND
            return 0
        return 1

    def CredFree(self, pointer):
        self.freed += 1


class FakeWindowsVault(vault.WindowsCredentialVault):
    def _last_error(self):
        return self._api.error


class WindowsMarshallingContract(Contract, unittest.TestCase):
    """The Credential Manager backend's ctypes plumbing, against a fake advapi32."""

    def make(self):
        self.api = FakeAdvapi32()
        return FakeWindowsVault(self.api)

    def test_the_blob_is_utf8_and_the_host_key_is_in_the_comment(self):
        self.vault.put(self.target(), SECRET, [FP_A, FP_B])
        blob, comment, user = self.api.store[self.target()]
        self.assertEqual(blob, SECRET.encode("utf-8"))
        self.assertEqual(comment, f"hostkey={FP_A},{FP_B}")
        self.assertEqual(user, "eleven")

    def test_every_read_is_freed_and_the_copy_cleared(self):
        self.vault.put(self.target(), SECRET, [FP_A])
        self.vault.get(self.target(), [FP_A])
        self.vault.get(self.target(), [FP_B])
        self.assertEqual(self.api.freed, 2)
        buffer, _ = self.api.live[0]
        self.assertEqual(bytes(buffer), b"\0" * len(buffer))

    def test_an_oversized_secret_is_refused(self):
        with self.assertRaises(vault.VaultError):
            self.vault.put(self.target(), "x" * 3000, [FP_A])
        self.assertEqual(self.api.store, {})

    def test_a_read_failure_is_an_error_not_a_miss(self):
        self.api.CredReadW = lambda *a: (setattr(self.api, "error", 5), 0)[1]
        with self.assertRaises(vault.VaultError):
            self.vault.get(self.target(), [FP_A])


class Selection(unittest.TestCase):

    def test_disabled_remembering_is_a_null_vault(self):
        chosen = vault.open_vault(enabled=False, platform="win32", env={})
        self.assertIsInstance(chosen, vault.NullVault)
        self.assertIn("turned off", chosen.available()[1])

    def test_windows_gets_credential_manager(self):
        chosen = vault.open_vault(enabled=True, platform="win32", env={})
        self.assertIsInstance(chosen, vault.WindowsCredentialVault)

    def test_linux_with_a_session_gets_secret_service(self):
        chosen = vault.open_vault(enabled=True, platform="linux",
                                  env={"DBUS_SESSION_BUS_ADDRESS": "x"},
                                  secret_service=lambda env: _Available())
        self.assertIsInstance(chosen, _Available)

    def test_linux_without_a_keyring_gets_a_null_vault_with_the_reason(self):
        chosen = vault.open_vault(enabled=True, platform="linux", env={})
        self.assertIsInstance(chosen, vault.NullVault)
        self.assertTrue(chosen.available()[1])

    def test_macos_is_not_supported_yet(self):
        chosen = vault.open_vault(enabled=True, platform="darwin", env={})
        self.assertIsInstance(chosen, vault.NullVault)
        self.assertIn("macOS", chosen.available()[1])


class _Available(vault.MemoryVault):
    pass


class Expiry(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.store = profiles.ProfileStore(os.path.join(self.dir, "profiles.json")).load()
        self.vault = vault.MemoryVault()
        self.now = datetime(2026, 10, 25, tzinfo=timezone.utc)

    def remember(self, days_ago):
        used = (self.now - timedelta(days=days_ago)).isoformat()
        profile = profiles.Profile(name="files", host="files.example.com", username="eleven",
                                   auth="password", password_saved=True,
                                   hostkey_fingerprints=[FP_A], created=used, last_used=used)
        self.store.save(profile)
        self.vault.put(vault.target_for(profile), SECRET, [FP_A])
        return profile

    def test_a_password_used_89_days_ago_is_kept(self):
        profile = self.remember(89)
        self.assertEqual(self.store.expire(self.vault, now=self.now), [])
        self.assertEqual(self.vault.get(vault.target_for(profile), [FP_A]), SECRET)

    def test_a_password_unused_for_91_days_is_deleted(self):
        profile = self.remember(91)
        self.assertEqual(self.store.expire(self.vault, now=self.now), ["files"])
        self.assertIsNone(self.vault.get(vault.target_for(profile), [FP_A]))
        self.assertFalse(self.store.get("files").password_saved)

    def test_nothing_expires_while_the_vault_is_unavailable(self):
        self.remember(200)
        self.assertEqual(self.store.expire(vault.NullVault("locked"), now=self.now), [])
        self.assertTrue(self.store.get("files").password_saved)


if __name__ == "__main__":
    unittest.main()
