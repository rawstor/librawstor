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
