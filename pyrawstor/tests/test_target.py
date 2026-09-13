import rawstor

import unittest
import tempfile


class TestTarget(unittest.TestCase):
    def test_create(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000001")

            target.create(size=1 << 20, mirrors=1)

            read_spec = target.spec()
            self.assertEqual(read_spec.size, 1 << 20)

            target.remove()

    def test_spec_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000002")

            self.assertRaises(FileNotFoundError, target.spec)

    def test_remove_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000003")

            self.assertRaises(FileNotFoundError, target.remove)

    def test_create_twice(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000004")

            target.create(size=1 << 20, mirrors=1)

            self.assertRaises(
                FileExistsError, target.create, size=1 << 20, mirrors=1)

            target.remove()
