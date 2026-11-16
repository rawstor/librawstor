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

OST = "0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6"
TENANT = "0198f1a2-3b4c-7d5e-8f90-0123456789ab"
MDS = "0198f1a2-3b4c-7d5e-8f90-fedcba987654"


class TestPki(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.dir = Path(self._temp.name)
        self.ca = self.dir / "ca"

    def test_init(self):
        pki.init(self.ca, "cluster.example", datetime.timedelta(days=1))

        self.assertEqual(stat.S_IMODE(os.stat(self.ca).st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE(os.stat(self.ca / "ca.key").st_mode), 0o600
        )
        self.assertEqual(pki.ca_file(self.ca), str(self.ca / "ca.crt"))
        self.assertTrue((self.ca / "ca.crt").exists())

    def test_init_twice(self):
        pki.init(self.ca, "cluster.example")
        with self.assertRaises(FileExistsError):
            pki.init(self.ca, "cluster.example")

    def test_bad_trust_domain(self):
        with self.assertRaises(OSError) as raised:
            pki.init(self.ca, "Not A Domain")
        self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_issue_and_renew(self):
        pki.init(self.ca, "cluster.example")
        cert = self.dir / "ost.crt"
        key = self.dir / "ost.key"

        identity = pki.issue_ost(self.ca, cert, key, OST, validity=3600)
        self.assertEqual(identity, f"spiffe://cluster.example/ost/{OST}")
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        old_key = key.read_bytes()

        renewed = pki.renew(self.ca, cert, key, datetime.timedelta(hours=2))
        self.assertEqual(renewed, identity)
        self.assertNotEqual(key.read_bytes(), old_key)

    def test_ost_without_an_id(self):
        pki.init(self.ca, "cluster.example")
        first = pki.issue_ost(self.ca, self.dir / "a.crt", self.dir / "a.key")
        second = pki.issue_ost(self.ca, self.dir / "b.crt", self.dir / "b.key")
        self.assertTrue(first.startswith("spiffe://cluster.example/ost/"))
        self.assertNotEqual(first, second)

    def test_mds_without_an_id(self):
        pki.init(self.ca, "cluster.example")
        first = pki.issue_mds(self.ca, self.dir / "a.crt", self.dir / "a.key")
        second = pki.issue_mds(self.ca, self.dir / "b.crt", self.dir / "b.key")
        self.assertTrue(first.startswith("spiffe://cluster.example/mds/"))
        self.assertNotEqual(first, second)

    def test_show(self):
        pki.init(self.ca, "cluster.example")
        other = self.dir / "other"
        pki.init(other, "cluster.example")
        cert = self.dir / "ost.crt"
        key = self.dir / "ost.key"
        identity = pki.issue_ost(self.ca, cert, key, OST, validity=3600)

        info = pki.show(cert)
        self.assertEqual(info.identity, identity)
        self.assertIsNone(info.issued)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.assertGreater(info.not_after, now)
        self.assertLess(info.not_after, now + datetime.timedelta(hours=2))

        self.assertTrue(pki.show(cert, self.ca).issued)
        self.assertFalse(pki.show(cert, other).issued)

    def test_show_what_is_not_a_certificate_of_a_process(self):
        pki.init(self.ca, "cluster.example")
        with self.assertRaises(FileNotFoundError):
            pki.show(self.dir / "none.crt")
        with self.assertRaises(OSError) as raised:
            pki.show(self.ca / "ca.crt")
        self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_roles(self):
        pki.init(self.ca, "cluster.example")
        crt = self.dir / "x.crt"
        key = self.dir / "x.key"
        self.assertEqual(
            pki.issue_mds(self.ca, crt, key, MDS),
            f"spiffe://cluster.example/mds/{MDS}",
        )
        self.assertEqual(
            pki.issue_admin(self.ca, "ops", crt, key),
            "spiffe://cluster.example/admin/ops",
        )
        self.assertEqual(
            pki.issue_client(self.ca, TENANT, "vm-1", crt, key, role="reader"),
            f"spiffe://cluster.example/tenant/{TENANT}/client/vm-1",
        )

    def test_client_permissions_survive_renewal(self):
        pki.init(self.ca, "cluster.example")
        crt, key = self.dir / "client.crt", self.dir / "client.key"
        permissions = {OST: 1, MDS: 0}
        pki.issue_client(self.ca, TENANT, "vm", crt, key,
                         role="manager", object_permissions=permissions)
        before = pki.show(crt)
        self.assertEqual(before.access_role, "manager")
        self.assertEqual(before.object_permissions, permissions)
        pki.renew(self.ca, crt, key)
        after = pki.show(crt)
        self.assertEqual(after.identity, before.identity)
        self.assertEqual(after.access_role, before.access_role)
        self.assertEqual(after.object_permissions, permissions)
        with self.assertRaises((OSError, ValueError)):
            pki.issue_client(self.ca, TENANT, "vm", crt, key,
                             role="manager", object_permissions={OST: 16})
        self.assertEqual(pki.show(crt).object_permissions, permissions)

    def test_none_with_object_permissions_survives_renewal(self):
        pki.init(self.ca, "cluster.example")
        crt, key = self.dir / "vhost.crt", self.dir / "vhost.key"
        pki.issue_client(self.ca, TENANT, "vhost", crt, key,
                         role="none", object_permissions={OST: 7})
        self.assertEqual(pki.show(crt).access_role, "none")
        self.assertEqual(pki.show(crt).object_permissions, {OST: 7})
        pki.renew(self.ca, crt, key)
        self.assertEqual(pki.show(crt).access_role, "none")
        self.assertEqual(pki.show(crt).object_permissions, {OST: 7})
        pki.issue_client(self.ca, TENANT, "empty", crt, key, role="none")
        self.assertEqual(pki.show(crt).access_role, "none")
        self.assertEqual(pki.show(crt).object_permissions, {})
        admin = self.dir / "admin.crt"
        pki.issue_admin(self.ca, "operator", admin, key)
        self.assertIsNone(pki.show(admin).access_role)

    def test_missing_ca(self):
        with self.assertRaises(FileNotFoundError):
            pki.issue_ost(self.ca, self.dir / "a.crt", self.dir / "a.key", OST)

    def test_bad_name(self):
        pki.init(self.ca, "cluster.example")
        with self.assertRaises(OSError) as raised:
            pki.issue_ost(
                self.ca, self.dir / "a.crt", self.dir / "a.key", "nobody"
            )
        self.assertEqual(raised.exception.errno, errno.EINVAL)
        self.assertIn("nobody", str(raised.exception))
        self.assertFalse((self.dir / "a.crt").exists())

    def test_bad_validity(self):
        with self.assertRaises(OSError) as raised:
            pki.init(self.ca, "cluster.example", validity=0)
        self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_renew_foreign_certificate(self):
        pki.init(self.ca, "cluster.example")
        other = self.dir / "other"
        pki.init(other, "cluster.example")
        cert = self.dir / "ost.crt"
        key = self.dir / "ost.key"
        pki.issue_ost(other, cert, key, OST)

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
