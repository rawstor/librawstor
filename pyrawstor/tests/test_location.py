import rawstor

import errno
from pathlib import Path
import unittest
import tempfile


class TestLocation(unittest.TestCase):
    def test_create(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            target = location.create(size=1 << 20, width=1)

            read_targets = list(location.objects())
            self.assertEqual(read_targets, [target])

            target.remove()

    def test_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")
            targets = list(location.objects())
            self.assertEqual(targets, [])

    def test_objects(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            targets = []
            for _ in range(10):
                target = location.create(size=1 << 20, width=1)
                targets.append(target)
            targets.sort()

            read_targets = list(location.objects())
            self.assertEqual(read_targets, targets)

            for target in targets:
                target.remove()

    def test_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}_not_found")
            self.assertRaises(FileNotFoundError, lambda: list(location.objects()))

    def test_info(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            info = location.info()
            self.assertEqual(info.used, 0)
            self.assertGreater(info.total, 0)

            target = location.create(size=1 << 20, width=1)

            info = location.info()
            stored_size = sum(
                path.stat().st_size
                for path in Path(temp_dir).rglob("*")
                if path.is_file()
            )
            self.assertGreater(stored_size, 1 << 20)
            self.assertEqual(info.used, stored_size)

            target.remove()
            self.assertEqual(location.info().used, 0)

    # file:// keeps no placement policy of its own; see
    # TestTarget.test_create_failure_domain_reaches_library.
    def test_create_failure_domain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            with self.assertRaises(OSError) as cm:
                location.create(size=1 << 20, width=1, failure_domain=256)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            target = location.create(
                size=1 << 20, width=1, failure_domain="server")
            self.assertEqual(list(location.objects()), [target])

            target.remove()

class TestWitnessLocation(unittest.TestCase):
    def test_plain_uris_and_metadata_discovery(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            paths = [stack.enter_context(tempfile.TemporaryDirectory())
                     for _ in range(3)]
            location = rawstor.Location(
                ','.join(f'file://{path}' for path in paths))
            target = location.create(size=65536, width=2)
            self.assertNotIn('witness+', target.uri)
            self.assertFalse(hasattr(target.spec(), 'witness_member'))
            self.assertEqual(target.spec().width, 2)

            metadata = target.meta()
            self.assertEqual([member.member_role for member in metadata],
                             [rawstor.MEMBER_DATA, rawstor.MEMBER_DATA,
                              rawstor.MEMBER_WITNESS])
            self.assertEqual(metadata[2].size, 65536)
            self.assertEqual(list(location.objects()), [target])
            target.remove()
            self.assertEqual(list(location.objects()), [])

    def test_odd_data_count_is_rejected(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            paths = [stack.enter_context(tempfile.TemporaryDirectory())
                     for _ in range(4)]
            location = rawstor.Location(
                ','.join(f'file://{path}' for path in paths))
            with self.assertRaises(OSError) as error:
                location.create(size=65536, width=3)
            self.assertEqual(error.exception.errno, errno.EINVAL)


class TestTenants(unittest.TestCase):
    TENANT = "0197e0a2-7c3b-7d4e-8f10-3a5b6c7d8e9f"
    OTHER = "0197e0a2-7c3b-7d4e-8f10-3a5b6c7d8ea0"

    def test_the_registry_is_the_mds(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")
            for call in (
                    lambda: list(location.tenants()),
                    lambda: location.create_tenant(self.TENANT),
                    lambda: location.remove_tenant(self.TENANT)):
                with self.assertRaises(OSError) as error:
                    call()
                self.assertEqual(error.exception.errno, errno.ENOTSUP)

    def test_an_object_has_the_tenant_of_its_location(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{self.TENANT}@{temp_dir}")

            target = location.create(size=1 << 20, width=1)

            self.assertEqual(target.tenant, self.TENANT)
            self.assertIn(f"{self.TENANT}@", target.uri)
            [meta] = target.meta()
            self.assertEqual(meta.tenant, self.TENANT)

    def test_the_default_tenant_is_not_named(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            target = location.create(size=1 << 20, width=1)

            self.assertNotIn("@", target.uri)
            self.assertEqual(target.tenant, rawstor.DEFAULT_TENANT)
            [meta] = target.meta()
            self.assertEqual(meta.tenant, rawstor.DEFAULT_TENANT)

    def test_a_location_lists_the_objects_of_its_tenant(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            acme = rawstor.Location(f"file://{self.TENANT}@{temp_dir}")
            other = rawstor.Location(f"file://{self.OTHER}@{temp_dir}")
            nobody = rawstor.Location(f"file://{temp_dir}")
            owned = acme.create(size=1 << 20, width=1)
            foreign = other.create(size=1 << 20, width=1)
            fallback = nobody.create(size=1 << 20, width=1)

            self.assertEqual(list(acme.objects()), [owned])
            self.assertEqual(list(other.objects()), [foreign])
            # The administrator sees every object, each target naming its
            # own owner.
            listed = sorted(nobody.objects(), key=lambda target: target.tenant)
            self.assertEqual(
                sorted(target.tenant for target in listed),
                sorted([self.TENANT, self.OTHER, rawstor.DEFAULT_TENANT]))
            self.assertEqual(
                sorted(listed), sorted([owned, foreign, fallback]))
