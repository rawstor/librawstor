import rawstor

import unittest

class TestBasics(unittest.TestCase):
    def test_hello(self):
        target = "xxx"
        rawstor.Object.create(target)
        rawstor.Object.remove(target)
