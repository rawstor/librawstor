import rawstor

import unittest

class TestBasics(unittest.TestCase):
    def test_hello(self):
        rawstor.initialize()
        rawstor.terminate()
