"""`/servers`, `/server connect <name>`, `/server forget…`, `/scan` and completion.

Covers openspec change `remembered-servers`, capability `server-profiles`:
listing never shows a secret, a remembered server connects by name, `/scan`
offers the matching profile, and forgetting removes profile and password.
"""

from __future__ import annotations

import unittest
from unittest import mock

from ssl_doctor import cli, tui, vault

from test_remembered_connect import FP_A, FakeSession, Harness


class ListServers(Harness):

    def test_nothing_remembered(self):
        output = self.run_cli("/servers")
        self.assertIn("No servers are remembered", output)
        self.assertIn("/server connect", output)

    def test_list_shows_settings_and_never_the_secret(self):
        for mode in (cli.ColorMode.PLAIN, cli.ColorMode.TRUECOLOR):
            with self.subTest(mode=mode):
                cli.set_color_mode(mode)
                self.addCleanup(cli.set_color_mode, cli.ColorMode.PLAIN)
                self.remember()
                self.remember(saved=False, name="web", host="10.0.0.5", auth="key",
                              key_path="~/.ssh/id_ed25519")
                output = self.run_cli("/servers")
                for text in ("files", "eleven@files.example.com:22", "password", "web",
                             "eleven@10.0.0.5:22", "key", "saved", "2026-"):
                    self.assertIn(text, output)
                self.assertNotIn("right", output)
                self.assertIn("key login", output)          # advice for password profiles


    def test_plain_mode_is_ascii_only(self):
        cli.set_color_mode(cli.ColorMode.PLAIN)
        self.remember()
        output = self.run_cli("/servers")
        self.assertTrue(output.isascii(), output)


class ConnectByName(Harness):

    def test_unknown_name_lists_the_closest(self):
        self.remember()
        output = self.run_cli("/server connect fles")
        self.assertIn("no remembered server named 'fles'", output)
        self.assertIn("files", output)
        self.assertEqual(FakeSession.instances, [])

    def test_profile_only_asks_just_for_the_password(self):
        self.remember(saved=False)
        self.passwords = ["right"]
        self.run_cli("/server connect files")
        self.assertEqual(self.asked, ["PASSWORD"])
        self.assertTrue(self.app.server.connected)

    def test_no_name_offers_recent_servers(self):
        self.remember(saved=False, name="old", host="old.example.com",
                      last_used="2026-10-01T00:00:00+00:00")
        self.remember(last_used="2026-10-24T00:00:00+00:00")
        self.answers = ["1"]                               # the most recent: files
        self.run_cli("/server connect")
        self.assertTrue(self.asked[0].startswith("server: 1=files  2=old"))
        self.assertEqual(FakeSession.instances[-1].cfg.host, "files.example.com")


class ScanOffersProfile(Harness):

    def scan(self, answers):
        self.answers = answers
        with mock.patch.object(cli.netchecks, "check_dns", return_value=(None, [])), \
                mock.patch.object(cli.netchecks, "check_tls_basic", return_value=(None, {})), \
                mock.patch.object(cli.netchecks, "domain_profile", return_value=None), \
                mock.patch.object(cli.SSLDoctorCLI, "_run_server_checks", create=True), \
                mock.patch.object(self.app.store, "extend"), \
                mock.patch.object(cli, "print_findings"):
            return self.run_cli("/scan files.example.com --server-only")

    def test_an_accepted_profile_connects_without_prompts(self):
        self.remember()
        self.scan(["yes"])
        self.assertTrue(self.asked[0].startswith("Use remembered server files"))
        self.assertEqual(len(self.asked), 1)
        self.assertEqual(FakeSession.instances[-1].cfg.host, "files.example.com")

    def test_a_declined_profile_falls_back_to_the_prompts(self):
        self.remember()
        self.scan(["no", ""])                              # decline, then empty hostname
        self.assertEqual(self.asked[1], "SSH hostname or IP")


class Forget(Harness):

    def test_forget_removes_profile_and_password(self):
        profile = self.remember()
        output = self.run_cli("/server forget files")
        self.assertIsNone(self.store.load().get("files"))
        self.assertIsNone(self.vault.get(vault.target_for(profile), [FP_A]))
        self.assertIn("forgot files", output)

    def test_forget_deletes_an_orphaned_vault_entry(self):
        profile = self.remember(saved=False)
        self.vault.put(vault.target_for(profile), "stale", [FP_A])
        self.run_cli("/server forget files")
        self.assertEqual(self.vault.items, {})

    def test_forget_password_keeps_the_profile(self):
        profile = self.remember()
        self.run_cli("/server forget-password files")
        self.assertFalse(self.store.load().get("files").password_saved)
        self.assertIsNone(self.vault.get(vault.target_for(profile), [FP_A]))

    def test_forget_all_needs_a_confirmation(self):
        self.remember()
        self.remember(saved=False, name="web", host="10.0.0.5")
        self.answers = ["no"]
        self.run_cli("/server forget --all")
        self.assertEqual(len(self.store.load().all()), 2)
        self.answers = ["yes"]
        self.run_cli("/server forget --all")
        self.assertEqual(self.store.load().all(), [])
        self.assertEqual(self.vault.items, {})

    def test_forget_unknown(self):
        output = self.run_cli("/server forget nothing")
        self.assertIn("no remembered server named 'nothing'", output)


class Completion(Harness):

    def test_commands_are_listed(self):
        names = [row[0] for row in cli.COMMANDS]
        self.assertIn("/servers", names)
        help_text = self.run_cli("/help")
        for text in ("/servers", "/server connect [name]", "/server forget", "--no-remember"):
            self.assertIn(text, help_text)

    def test_profile_names_complete_after_connect_and_forget(self):
        self.remember()
        self.remember(saved=False, name="web", host="10.0.0.5")
        complete = self.app._completer()
        self.assertEqual([r[0] for r in complete("/server connect ")],
                         ["/server connect files", "/server connect web"])
        self.assertEqual([r[0] for r in complete("/server forget w")], ["/server forget web"])
        self.assertEqual(complete("/scan "), [])
        self.assertEqual(complete("/serv")[0][0], "/server")

    def test_the_shell_menu_opens_for_argument_completion(self):
        self.remember()
        session = tui.TuiSession(renderer=lambda s: ([], (1, 1)),
                                 completer=self.app._completer())
        session.input = "/server connect f"
        session.refresh_menu()
        self.assertEqual(session.menu[0][0], "/server connect files")
        session.accept_completion()
        self.assertEqual(session.input, "/server connect files ")
        session.input = "/scan example.com"
        session.refresh_menu()
        self.assertEqual(session.menu, [])


if __name__ == "__main__":
    unittest.main()
