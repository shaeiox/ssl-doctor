"""self-hosted-deployment 12.4: signed offline bundle verifies; tampering is caught.

Needs a build in dist/<os> (packaging/build.py); skipped otherwise.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist", "linux")
sys.path.insert(0, os.path.join(ROOT, "packaging"))


def have_build():
    import importlib.util
    return (os.path.exists(os.path.join(DIST, "ssl-doctor")) and shutil.which("openssl")
            and importlib.util.find_spec("cyclonedx_py") is not None)


@unittest.skipUnless(have_build(), "no Linux build in dist/linux (run packaging/build.py)")
class ReleaseBundleTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import release
        cls.release = release
        cls.out = tempfile.mkdtemp(prefix="ssldoctor-release-")
        key = os.path.join(cls.out, "key.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", key], check=True)
        cls.archive = release.build(DIST, key, cls.out)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out, ignore_errors=True)

    def fresh(self):
        """Extract the archive into a new directory (each test tampers its own copy)."""
        import tarfile
        d = tempfile.mkdtemp(dir=self.out)
        with tarfile.open(self.archive) as t:
            t.extractall(d)
        return os.path.join(d, os.listdir(d)[0])

    def test_bundle_contents(self):
        b = self.fresh()
        for rel in ("bin/ssl-doctor", "bin/ssl-doctor-agent", "ssldoctor-server/ssldoctor-server",
                    "systemd/ssldoctor-server.service", "VERIFY.md", "docs/INSTALL.md",
                    "sbom.cdx.json", "RELEASE-KEY.pub", "SHA256SUMS", "SHA256SUMS.sig"):
            self.assertTrue(os.path.exists(os.path.join(b, rel)), rel)
        import json
        with open(os.path.join(b, "sbom.cdx.json")) as fh:
            names = {c["name"].lower() for c in json.load(fh)["components"]}
        self.assertTrue({"fastapi", "psycopg", "python3-saml"} <= names, names)

    def test_untampered_bundle_verifies(self):
        self.assertEqual(self.release.verify(self.fresh())[:2], (True, True))

    def test_modified_file_fails_checksums(self):
        b = self.fresh()
        with open(os.path.join(b, "bin", "ssl-doctor"), "ab") as fh:
            fh.write(b"\x00")
        sig_ok, files_ok, _ = self.release.verify(b)
        self.assertTrue(sig_ok)
        self.assertFalse(files_ok)

    def test_forged_checksum_fails_signature(self):
        b = self.fresh()
        target = os.path.join(b, "bin", "ssl-doctor")
        with open(target, "ab") as fh:
            fh.write(b"\x00")
        new = hashlib.sha256(open(target, "rb").read()).hexdigest()
        sums = os.path.join(b, "SHA256SUMS")
        lines = [(f"{new}  bin/ssl-doctor\n" if l.endswith("  bin/ssl-doctor\n") else l)
                 for l in open(sums)]
        with open(sums, "w") as fh:
            fh.writelines(lines)
        sig_ok, files_ok, _ = self.release.verify(b)
        self.assertTrue(files_ok)            # attacker made the list consistent ...
        self.assertFalse(sig_ok)             # ... but cannot re-sign it

    def test_documented_commands_work(self):
        b = self.fresh()
        sig = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                              "RELEASE-KEY.pub", "-rawin", "-in", "SHA256SUMS",
                              "-sigfile", "SHA256SUMS.sig"], cwd=b, capture_output=True,
                             text=True)
        self.assertIn("Signature Verified Successfully", sig.stdout)
        self.assertEqual(subprocess.run(["sha256sum", "-c", "--strict", "--quiet",
                                         "SHA256SUMS"], cwd=b).returncode, 0)


if __name__ == "__main__":
    unittest.main()
