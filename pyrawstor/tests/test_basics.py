import rawstor

import unittest
import tempfile


class TestBasics(unittest.TestCase):
    def test_basics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = f'file://{temp_dir}'

            spec = rawstor.ObjectSpec(size=1 << 20)
            target = rawstor.Object.create_at(location, spec)
            self.addCleanup(rawstor.Object.remove, target)

            read_spec = rawstor.Object.spec(target)
            self.assertEqual(read_spec.size, 1 << 20)

            read_targets = rawstor.Object.list(location)
            self.assertEqual(list(read_targets), [target])

    def test_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = f'file://{temp_dir}'
            targets = rawstor.Object.list(location)
            self.assertEqual(list(targets), [])

    def test_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = f'file://{temp_dir}'

            targets = []
            for _ in range(10):
                spec = rawstor.ObjectSpec(size=1 << 20)
                target = rawstor.Object.create_at(location, spec)
                self.addCleanup(rawstor.Object.remove, target)
                targets.append(target)

            read_targets = rawstor.Object.list(location)
            self.assertEqual(list(read_targets), targets)
