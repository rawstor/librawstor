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

            total, page = rawstor.Object.list(location, 0, 10)
            self.assertEqual(total, 1)
            self.assertEqual(page, [target])

    def test_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = f'file://{temp_dir}'
            total, page = rawstor.Object.list(location, 0, 10)
            self.assertEqual(total, 0)
            self.assertEqual(page, [])

    def test_pagination(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = f'file://{temp_dir}'

            targets = []
            for _ in range(10):
                spec = rawstor.ObjectSpec(size=1 << 20)
                target = rawstor.Object.create_at(location, spec)
                self.addCleanup(rawstor.Object.remove, target)
                targets.append(target)

            total, page = rawstor.Object.list(location, 0, 3)
            self.assertEqual(total, 10)
            self.assertEqual(page, targets[0:3])

            total, page = rawstor.Object.list(location, 1, 3)
            self.assertEqual(total, 10)
            self.assertEqual(page, targets[1:4])

            total, page = rawstor.Object.list(location, 8, 3)
            self.assertEqual(total, 10)
            self.assertEqual(page, targets[8:10])

            total, page = rawstor.Object.list(location, 9, 3)
            self.assertEqual(total, 10)
            self.assertEqual(page, targets[9:10])

            total, page = rawstor.Object.list(location, 10, 3)
            self.assertEqual(total, 10)
            self.assertEqual(page, [])
