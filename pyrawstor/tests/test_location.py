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

            read_targets = list(location)
            self.assertEqual(read_targets, [target])

            target.remove()

    def test_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")
            targets = list(location)
            self.assertEqual(targets, [])

    def test_iter(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            targets = []
            for _ in range(10):
                target = location.create(size=1 << 20, width=1)
                targets.append(target)
            targets.sort()

            read_targets = list(location)
            self.assertEqual(read_targets, targets)

            for target in targets:
                target.remove()

    def test_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}_not_found")
            self.assertRaises(FileNotFoundError, lambda: list(location))

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
            self.assertEqual(list(location), [target])

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
                              rawstor.MEMBER_META])
            self.assertEqual(metadata[2].size, 65536)
            self.assertEqual(list(location), [target])
            target.remove()
            self.assertEqual(list(location), [])

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
