import rawstor

import unittest
import tempfile

class TestBasics(unittest.TestCase):
    def test_hello(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            spec = rawstor.ObjectSpec(size=1 << 20)
            location = f'file://{temp_dir}'
            target = rawstor.Object.create_at(location, spec)
            read_spec = rawstor.Object.spec(target)
            self.assertEqual(read_spec.size, 1 << 20)
            rawstor.Object.remove(target)
