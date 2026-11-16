import datetime
import errno
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rawstor import pki

OST = "spiffe://cluster.example/ost/0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6"


class TestPki(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.dir = Path(self._temp.name)
        self.ca = self.dir / "ca"

    def test_init(self):
        pki.init(self.ca, "test CA", datetime.timedelta(days=1))

        self.assertEqual(stat.S_IMODE(os.stat(self.ca).st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE(os.stat(self.ca / "ca.key").st_mode), 0o600
        )
        self.assertEqual(pki.ca_file(self.ca), str(self.ca / "ca.crt"))
        self.assertTrue((self.ca / "ca.crt").exists())

    def test_init_twice(self):
        pki.init(self.ca)
        with self.assertRaises(FileExistsError):
            pki.init(self.ca)

    def test_issue_and_renew(self):
        pki.init(self.ca)
        cert = self.dir / "ost.crt"
        key = self.dir / "ost.key"

        pki.issue(self.ca, OST, cert, key, validity=3600)
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        old_key = key.read_bytes()

        pki.renew(self.ca, cert, key, datetime.timedelta(hours=2))
        self.assertNotEqual(key.read_bytes(), old_key)

    def test_missing_ca(self):
        with self.assertRaises(FileNotFoundError):
            pki.issue(
                self.ca, OST, self.dir / "a.crt", self.dir / "a.key"
            )

    def test_bad_identity(self):
        pki.init(self.ca)
        with self.assertRaises(OSError) as raised:
            pki.issue(
                self.ca, "nobody", self.dir / "a.crt", self.dir / "a.key"
            )
        self.assertEqual(raised.exception.errno, errno.EINVAL)
        self.assertIn("nobody", str(raised.exception))
        self.assertFalse((self.dir / "a.crt").exists())

    def test_bad_validity(self):
        with self.assertRaises(OSError) as raised:
            pki.init(self.ca, validity=0)
        self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_renew_foreign_certificate(self):
        pki.init(self.ca)
        other = self.dir / "other"
        pki.init(other)
        cert = self.dir / "ost.crt"
        key = self.dir / "ost.key"
        pki.issue(other, OST, cert, key)

        with self.assertRaises(OSError) as raised:
            pki.renew(self.ca, cert, key)
        self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_does_not_start_rawstor(self):
        # Importing it must not load librawstor, which would start rawstor
        # and want the TLS settings this module makes.
        code = (
            "import sys\n"
            "from rawstor import pki\n"
            "assert 'rawstor.librawstor' not in sys.modules\n"
            "import rawstor\n"
            "assert 'rawstor.librawstor' not in sys.modules\n"
        )
        root = str(Path(pki.__file__).resolve().parent.parent)
        env = dict(os.environ, PYTHONPATH=root)
        subprocess.run([sys.executable, "-c", code], check=True, env=env)
