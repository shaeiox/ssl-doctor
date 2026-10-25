"""`/server config show|set|clear`: per-server nginx settings, saved and reused.

Covers openspec change `nginx-cert-path-resolution`, capability
`server-diagnostic-settings`.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from ssl_doctor import cli, profiles, vault

from test_remembered_connect import FP_A, FakeSession, Harness

CERT = "/opt/pvm/nginx/conf/ssl/fullchain.pem"
KEY = "/opt/pvm/nginx/conf/ssl/private.key"


class ServerConfig(Harness):

    def connect_files(self):
        self.remember()
        self.run_cli("/server connect files")
        self.assertTrue(self.app.server.connected)

    def test_set_while_connected_saves_for_that_server_only(self):
        self.connect_files()
        before = self.store.load().get("files").to_dict()
        output = self.run_cli(f"/server config set --cert {CERT} --key {KEY}")
        after = self.store.load().get("files")
        self.assertEqual((after.nginx_mode, after.nginx_cert, after.nginx_key), ("manual", CERT, KEY))
        changed = {k for k, v in after.to_dict().items() if before.get(k) != v}
        self.assertEqual(changed, {"nginx_mode", "nginx_cert", "nginx_key"})
        self.assertEqual(self.app.server.nginx_settings.cert, CERT)      # applied now
        self.assertIn("files", output)

    def test_set_for_a_named_server_while_disconnected(self):
        self.remember()
        self.remember(saved=False, name="web", host="10.0.0.5")
        self.run_cli("/server config set web --cert /etc/ssl/web.pem")
        self.assertEqual(self.store.load().get("web").nginx_cert, "/etc/ssl/web.pem")
        self.assertEqual(self.store.load().get("files").nginx_mode, "auto")

    def test_reconnect_after_restart_reuses_the_paths_without_asking(self):
        self.connect_files()
        self.run_cli(f"/server config set --cert {CERT} --key {KEY}")
        # a new CLI process with the same profile file and vault
        self.app = restarted = cli.SSLDoctorCLI()
        restarted._profile_store = profiles.ProfileStore(self.store.path).load()
        restarted._secret_vault = self.vault
        restarted._interactive_session = lambda: True
        restarted.prompt = self._prompt
        self.asked.clear()
        output = self.run_cli("/server connect files")
        self.assertEqual(self.asked, [])                                  # no path, no password
        self.assertEqual(restarted.server.nginx_settings.cert, CERT)
        self.assertEqual(restarted.server.nginx_settings.mode, "manual")
        self.assertIn("nginx settings", output)

    def test_another_server_does_not_inherit(self):
        self.connect_files()
        self.run_cli(f"/server config set --cert {CERT}")
        self.remember(saved=False, name="web", host="10.0.0.5")
        self.passwords = ["right"]
        self.run_cli("/server connect web")
        self.assertEqual(self.app.server.nginx_settings.mode, "auto")
        self.assertEqual(self.app.server.nginx_settings.cert, "")

    def test_clear_returns_to_automatic_and_keeps_the_password(self):
        profile = self.remember()
        self.run_cli(f"/server config set files --cert {CERT}")
        self.run_cli("/server config clear files")
        after = self.store.load().get("files")
        self.assertEqual((after.nginx_mode, after.nginx_cert), ("auto", ""))
        self.assertEqual(self.vault.get(vault.target_for(profile), [FP_A]), "right")

    def test_show(self):
        self.connect_files()
        output = self.run_cli("/server config show")
        self.assertIn("files", output)
        self.assertIn("automatic discovery", output)
        self.run_cli(f"/server config set --cert {CERT}")
        output = self.run_cli("/server config show")
        self.assertIn("manual", output)
        self.assertIn(CERT, output)

    def test_invalid_relative_path_is_refused(self):
        self.connect_files()
        output = self.run_cli("/server config set --cert ssl/fullchain.pem")
        self.assertIn("absolute path", output)
        self.assertEqual(self.store.load().get("files").nginx_mode, "auto")

    def test_prompts_when_no_flags_are_given(self):
        self.connect_files()
        self.answers = [CERT, KEY, None, None]
        self.run_cli("/server config set")
        self.assertEqual(self.store.load().get("files").nginx_key, KEY)
        self.assertTrue(self.asked[0].startswith("certificate path"))

    def test_unremembered_server_can_be_remembered_for_the_settings(self):
        self.answers = self.NEW_SERVER + ["n"]                  # connect, do not remember yet
        self.passwords = ["right"]
        self.run_cli("/server connect")
        self.answers = ["yes"]
        self.run_cli(f"/server config set --cert {CERT}")
        saved = self.store.load().all()
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0].nginx_cert, CERT)

    def test_unremembered_server_declined_is_session_only(self):
        self.answers = self.NEW_SERVER + ["n"]
        self.passwords = ["right"]
        self.run_cli("/server connect")
        self.answers = ["no"]
        output = self.run_cli(f"/server config set --cert {CERT}")
        self.assertEqual(self.store.load().all(), [])
        self.assertEqual(self.app.server.nginx_settings.cert, CERT)
        self.assertIn("this session only", output)

    def test_remembering_off_is_session_only(self):
        self.connect_files()
        os.environ["SSL_DOCTOR_REMEMBER"] = "off"
        output = self.run_cli(f"/server config set --cert {CERT}")
        self.assertEqual(self.store.load().get("files").nginx_mode, "auto")
        self.assertEqual(self.app.server.nginx_settings.cert, CERT)
        self.assertIn("not saved", output)

    def test_password_expiry_keeps_the_settings(self):
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        self.remember(last_used=old, created=old)
        self.run_cli(f"/server config set files --cert {CERT}")
        p = self.store.load().get("files")
        p.last_used = old
        self.store.save(p)
        self.assertEqual(self.store.expire(self.vault), ["files"])
        after = self.store.load().get("files")
        self.assertFalse(after.password_saved)
        self.assertEqual(after.nginx_cert, CERT)

    def test_no_password_in_the_profile_file(self):
        self.connect_files()
        self.run_cli(f"/server config set --cert {CERT} --key {KEY}")
        with open(self.store.path) as fh:
            text = fh.read()
        self.assertNotIn("right", text)
        self.assertIn(CERT, json.loads(text)["profiles"][0]["nginx_cert"])

    def test_bare_server_config_keeps_its_meaning(self):
        self.connect_files()
        calls = []
        self.app.server.tls_config_scan = lambda emit=None: calls.append(1) or []
        self.run_cli("/server config")
        self.assertEqual(calls, [1])

    def test_help_and_completion(self):
        help_text = self.run_cli("/help")
        for row in ("/server config show [name]", "/server config set [name]",
                    "/server config clear [name]"):
            self.assertIn(row, help_text)
        self.remember()
        complete = self.app._completer()
        self.assertEqual([r[0] for r in complete("/server config s")],
                         ["/server config set", "/server config show"])
        self.assertEqual([r[0] for r in complete("/server config set ")],
                         ["/server config set files"])


class BatchMode(Harness):

    def test_batch_set_saves_nothing_and_says_why(self):
        self.remember(saved=False, name="web", host="10.0.0.5")
        self.app._BATCH_MODE = True
        output = self.run_cli("/server config set web --cert /etc/ssl/web.pem")
        self.assertEqual(self.store.load().get("web").nginx_mode, "auto")
        self.assertIn("nothing was saved", output)
        self.assertEqual(self.asked, [])

    def test_batch_connect_still_uses_saved_settings(self):
        profile = self.remember()
        profile.nginx_mode, profile.nginx_cert = "manual", CERT
        self.store.save(profile)
        self.app._BATCH_MODE = True
        self.run_cli("/server connect files")
        self.assertEqual(self.app.server.nginx_settings.cert, CERT)
