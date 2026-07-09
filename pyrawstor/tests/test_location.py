import rawstor

import unittest
import tempfile


class TestLocation(unittest.TestCase):
    def test_create(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            target = location.create(size=1 << 20)

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
                target = location.create(size=1 << 20)
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
