"""client-machine-diagnostics: checks about the machine running SSL Doctor.

Audit A: `local.certutil` was FAIL whenever the word "error" appeared anywhere
in a successful `certutil -verify` output.
"""

import subprocess
import unittest
from unittest import mock

from ssl_doctor import findings as F
from ssl_doctor import local

SUCCESS_TAIL = "Leaf certificate revocation check passed\nCertUtil: -verify command completed successfully.\n"

CHAIN_DUMP = """Issuer:
    CN=Example Intermediate
Subject:
    CN=www.example.com
-------- CERT_CHAIN_CONTEXT --------
ChainContext.dwInfoStatus = CERT_TRUST_HAS_PREFERRED_ISSUER (0x100)
SimpleChain.dwInfoStatus = CERT_TRUST_HAS_PREFERRED_ISSUER (0x100)
CertContext[0][0]: dwInfoStatus=102 dwErrorStatus=0
  Issuer: CN=Example Intermediate
Exclude leaf cert:
Full chain:
""" + SUCCESS_TAIL

URL_FAILURE = ('  Failed "CDP" Time: 0\n'
               "    Error retrieving URL: The server name or address could not be resolved "
               "0x80072ee7 (WinHttp: 12007 ERROR_WINHTTP_NAME_NOT_RESOLVED)\n"
               "    http://crl.example.com/int.crl\n" + SUCCESS_TAIL)

CHAINING_FAILED = ("CertUtil: -verify command FAILED: 0x800b010a (-2146762486 CERT_E_CHAINING)\n"
                   "CertUtil: A certificate chain could not be built to a trusted root "
                   "authority.\n")


def certutil(stdout="", rc=0, stderr="", raises=None):
    """Run check_certutil_verify as on Windows, with certutil's result mocked."""
    run = mock.Mock(side_effect=raises) if raises else mock.Mock(
        return_value=subprocess.CompletedProcess([], rc, stdout, stderr))
    with mock.patch.object(local, "IS_WINDOWS", True), \
            mock.patch.object(local.shutil, "which", return_value=r"C:\Windows\certutil.exe"), \
            mock.patch.object(local.subprocess, "run", run):
        return local.check_certutil_verify("leaf.cer")


class CertutilResult(unittest.TestCase):

    def test_regression_a_success_with_a_chain_dump(self):
        self.assertEqual(certutil(CHAIN_DUMP).status, F.PASS)

    def test_error_inside_a_certificate_name(self):
        out = "Subject:\n    CN=error-reporting.example.com\n" + SUCCESS_TAIL
        self.assertEqual(certutil(out).status, F.PASS)

    def test_unreachable_cdp_url_is_not_a_chain_failure(self):
        f = certutil(URL_FAILURE)
        self.assertEqual(f.status, F.PASS)
        self.assertTrue(any("could not be retrieved" in e and "crl.example.com" in e
                            for e in f.evidence), f.evidence)

    def test_localised_success(self):
        out = ("Überprüfung der Sperrung des Endzertifikats erfolgreich\n"
               "CertUtil: -verify-Befehl wurde erfolgreich ausgeführt.\n")
        self.assertEqual(certutil(out).status, F.PASS)

    def test_chain_cannot_be_built(self):
        f = certutil(CHAINING_FAILED, rc=0x800b010a)
        self.assertEqual(f.status, F.FAIL)
        self.assertTrue(any("0x800b010a" in e for e in f.evidence), f.evidence)

    def test_failure_code_from_the_exit_status(self):
        f = certutil("CertUtil: -verify-Befehl ist FEHLGESCHLAGEN\n", rc=0x80092012)
        self.assertEqual(f.status, F.FAIL)
        self.assertTrue(any("0x80092012" in e for e in f.evidence), f.evidence)

    def test_access_denied_when_starting_certutil(self):
        f = certutil(raises=PermissionError(13, "Access is denied"))
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertTrue(any("Access is denied" in e for e in f.evidence), f.evidence)

    def test_timeout(self):
        f = certutil(raises=subprocess.TimeoutExpired("certutil", 60))
        self.assertEqual(f.status, F.NOT_TESTED)


if __name__ == "__main__":
    unittest.main()
