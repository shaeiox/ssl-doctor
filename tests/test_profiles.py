"""Remembered server profiles: validation, private atomic storage, lookups.

Covers openspec change `remembered-servers`, capability `server-profiles`:
a profile holds only non-secret settings, the file is treated as untrusted
input, and every save is atomic and owner-only.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from ssl_doctor import profiles

FP = "SHA256:" + "A" * 43


def sample(**over):
    data = dict(name="files", host="files.example.com", port=22, username="eleven",
                auth="password", tls_host="files.example.com", tls_port=443,
                password_saved=True, hostkey_fingerprints=[FP],
                created="2026-10-25T10:00:00+00:00", last_used="2026-10-25T10:00:00+00:00")
    data.update(over)
    return profiles.Profile(**data)


class Workspace(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "profiles.json")
        self.warnings = []

    def store(self):
        store = profiles.ProfileStore(self.path, warn=self.warnings.append)
        store.load()
        return store

    def write_raw(self, text):
        with open(self.path, "w") as fh:
            fh.write(text)


class Validation(unittest.TestCase):

    def test_a_valid_profile_round_trips(self):
        profile = sample()
        self.assertEqual(profiles.Profile.from_dict(profile.to_dict()), profile)

    def test_invalid_values_are_rejected(self):
        bad = {
            "name": "files server",          # space
            "port": 70000,
            "auth": "telnet",
            "host": "-oProxyCommand=nc",     # would become an ssh option
            "username": "-oProxyCommand=x",
            "tls_port": 0,
            "hostkey_fingerprints": ["MD5:aa"],
            "last_used": "yesterday",
            "key_path": "-i/tmp/k",
        }
        for field, value in bad.items():
            with self.subTest(field=field):
                data = sample().to_dict()
                data[field] = value
                with self.assertRaises(ValueError):
                    profiles.Profile.from_dict(data)

    def test_a_profile_has_no_field_for_a_secret(self):
        names = {f for f in sample().to_dict()}
        for forbidden in ("password", "secret", "passphrase", "private_key", "ssh_options"):
            self.assertNotIn(forbidden, names)

    def test_default_names_follow_the_host(self):
        self.assertEqual(profiles.default_name("files.cloudavid.com", set()), "files")
        self.assertEqual(profiles.default_name("files.cloudavid.com", {"files"}),
                         "files.cloudavid.com")
        self.assertEqual(profiles.default_name("10.0.0.5", set()), "10.0.0.5")


class Loading(Workspace):

    def test_unknown_fields_are_dropped(self):
        data = sample().to_dict()
        data["proxy_command"] = "nc evil 22"
        self.write_raw(json.dumps({"schema": 1, "profiles": [data]}))
        store = self.store()
        self.assertNotIn("proxy_command", store.get("files").to_dict())

    def test_an_invalid_entry_is_skipped_with_a_warning(self):
        good, bad = sample().to_dict(), sample(name="other").to_dict()
        bad["port"] = "22; rm -rf /"
        self.write_raw(json.dumps({"schema": 1, "profiles": [good, bad]}))
        store = self.store()
        self.assertEqual([p.name for p in store.all()], ["files"])
        self.assertTrue(any("other" in w for w in self.warnings))

    def test_a_corrupt_file_is_ignored_and_left_alone(self):
        self.write_raw("{not json")
        store = self.store()
        self.assertEqual(store.all(), [])
        self.assertTrue(store.read_only)
        self.assertTrue(self.warnings)
        with open(self.path) as fh:
            self.assertEqual(fh.read(), "{not json")

    def test_a_missing_file_is_an_empty_store(self):
        store = self.store()
        self.assertEqual(store.all(), [])
        self.assertFalse(store.read_only)
        self.assertFalse(self.warnings)


class Saving(Workspace):

    def test_save_then_load(self):
        self.store().save(sample())
        self.assertEqual(self.store().get("files"), sample())

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_the_file_is_owner_only(self):
        self.store().save(sample())
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_a_failed_replace_keeps_the_previous_file(self):
        self.store().save(sample())
        with open(self.path) as fh:
            before = fh.read()
        with mock.patch.object(profiles.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.store().save(sample(name="other", host="other.example.com"))
        with open(self.path) as fh:
            self.assertEqual(fh.read(), before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))

    def test_two_stores_do_not_lose_each_others_profiles(self):
        first, second = self.store(), self.store()
        first.save(sample())
        second.save(sample(name="other", host="other.example.com"))
        self.assertEqual(sorted(p.name for p in self.store().all()), ["files", "other"])

    def test_saving_over_a_corrupt_file_moves_it_aside(self):
        self.write_raw("{not json")
        store = self.store()
        store.save(sample())
        aside = [n for n in os.listdir(self.dir) if n.startswith("profiles.json.bad-")]
        self.assertEqual(len(aside), 1)
        self.assertEqual([p.name for p in self.store().all()], ["files"])

    def test_forget_removes_only_that_profile(self):
        store = self.store()
        store.save(sample())
        store.save(sample(name="other", host="other.example.com"))
        self.assertTrue(store.forget("files"))
        self.assertFalse(store.forget("files"))
        self.assertEqual([p.name for p in self.store().all()], ["other"])


class Lookups(Workspace):

    def setUp(self):
        super().setUp()
        store = self.store()
        store.save(sample(last_used="2026-10-20T10:00:00+00:00"))
        store.save(sample(name="web", host="10.0.0.5", tls_host="www.example.com",
                          last_used="2026-10-24T10:00:00+00:00"))
        store.save(sample(name="mail", host="mail.example.com", tls_host="",
                          last_used="2026-10-22T10:00:00+00:00"))
        self.lookups = self.store()

    def test_get_and_closest(self):
        self.assertEqual(self.lookups.get("web").host, "10.0.0.5")
        self.assertIsNone(self.lookups.get("fles"))
        self.assertEqual(self.lookups.closest("fles"), ["files"])

    def test_recent_is_newest_first(self):
        self.assertEqual([p.name for p in self.lookups.recent(2)], ["web", "mail"])

    def test_match_domain_prefers_the_tls_target(self):
        self.assertEqual(self.lookups.match_domain("WWW.example.com").name, "web")
        self.assertEqual(self.lookups.match_domain("mail.example.com").name, "mail")
        self.assertIsNone(self.lookups.match_domain("nothing.example.com"))

    def test_for_host_finds_the_profile_to_prefill(self):
        self.assertEqual(self.lookups.for_host("files.example.com").name, "files")
        self.assertIsNone(self.lookups.for_host("unknown.example.com"))


if __name__ == "__main__":
    unittest.main()
