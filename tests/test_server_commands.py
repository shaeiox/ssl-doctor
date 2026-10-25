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


class ScanAsksWhichServer(Harness):
    """Every interactive /scan asks which server to use (current, remembered, new)."""

    def scan(self, answers, domain="files.example.com"):
        self.answers = list(answers)
        self.asked.clear()
        with mock.patch.object(cli.netchecks, "check_dns", return_value=(None, [])), \
                mock.patch.object(cli.netchecks, "check_tls_basic", return_value=(None, {})), \
                mock.patch.object(cli.netchecks, "domain_profile", return_value=None), \
                mock.patch.object(self.app.store, "extend"), \
                mock.patch.object(cli, "print_findings"):
            return self.run_cli(f"/scan {domain} --server-only")

    def connect_files(self):
        self.remember()
        self.run_cli("/server connect files")
        self.assertTrue(self.app.server.connected)
        return len(FakeSession.instances)

    def test_a_second_scan_of_another_domain_asks_instead_of_reusing(self):
        self.connect_files()
        output = self.scan(["n", ""], domain="www.example.org")    # new server, then give up
        self.assertTrue(self.asked[0].startswith("server for this scan"))
        self.assertIn("current session", output)
        self.assertEqual(self.asked[1], "SSH hostname or IP")

    def test_the_matching_remembered_server_is_the_default(self):
        self.remember()
        self.remember(saved=False, name="web", host="10.0.0.5", tls_host="www.example.org",
                      last_used="2026-10-30T00:00:00+00:00")
        self.scan([None])                                          # Enter
        self.assertEqual(len(self.asked), 1)
        self.assertEqual(FakeSession.instances[-1].cfg.host, "files.example.com")

    def test_keeping_the_current_session_does_not_reconnect(self):
        sessions = self.connect_files()
        output = self.scan([None])                                 # default: current session
        self.assertEqual(len(FakeSession.instances), sessions)
        self.assertIn("using the current session", output)

    def test_a_remembered_server_can_be_chosen_by_name(self):
        self.remember()
        self.remember(name="web", host="10.0.0.5", tls_host="www.example.org")
        self.scan(["web"])
        self.assertEqual(FakeSession.instances[-1].cfg.host, "10.0.0.5")

    def test_a_new_server_replaces_the_session_once_it_connects(self):
        self.connect_files()
        old = self.app.server
        self.passwords = ["right"]
        self.scan(["n", "other.example.com", "22", "eleven", "1", "", "443", "n"])
        self.assertIsNot(self.app.server, old)
        self.assertFalse(old.connected)
        self.assertEqual(self.app.server.cfg.host, "other.example.com")

    def test_a_failed_new_server_keeps_the_session_and_stops_the_scan(self):
        self.connect_files()
        old = self.app.server
        self.passwords = ["wrong"]
        with mock.patch.object(FakeSession, "overview", create=True,
                               side_effect=AssertionError("server checks ran")) as checks:
            self.scan(["n", "other.example.com", "22", "eleven", "1", "", "443"])
        self.assertIs(self.app.server, old)
        self.assertTrue(old.connected)
        checks.assert_not_called()

    def test_nothing_to_choose_from_goes_straight_to_the_prompts(self):
        self.scan([""])                                            # empty hostname: stop
        self.assertEqual(self.asked, ["SSH hostname or IP"])

    def test_an_unrecognised_answer_skips_the_server_step(self):
        self.remember()
        output = self.scan(["7"])
        self.assertIn("not a listed server", output)
        self.assertEqual(FakeSession.instances, [])

    def test_batch_scans_never_ask(self):
        sessions = self.connect_files()
        self.app._BATCH_MODE = True
        self.scan([])
        self.assertEqual(self.asked, [])
        self.assertEqual(len(FakeSession.instances), sessions)


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
