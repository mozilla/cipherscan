# Copyright (c) 2015 Hubert Kario
# Released under Mozilla Public License Version 2.0

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from cscan.config import HugeCipherList, Firefox_42
from cscan.modifiers import truncate_ciphers_to_size, append_ciphers_to_size, \
        extend_with_ext_to_size

class TestTruncateCiphersToSize(unittest.TestCase):
    def test_with_big_hello(self):
        gen = HugeCipherList()

        self.assertGreater(len(gen(b'localhost').write()), 2**14)
        self.assertEqual(gen(b'localhost').cipher_suites[0], 49196)

        gen = truncate_ciphers_to_size(gen, 2**12)

        self.assertEqual(len(gen(b'localhost').write()), 2**12-1)
        self.assertEqual(gen(b'localhost').cipher_suites[0], 49196)

class TestAppendCiphersToSize(unittest.TestCase):
    def test_with_small_hello(self):
        gen = Firefox_42()

        self.assertLess(len(gen(b'localhost').write()), 2**10)
        self.assertEqual(gen(b'localhost').cipher_suites[0], 49195)

        gen = append_ciphers_to_size(gen, 2**12)

        self.assertEqual(len(gen(b'localhost').write()), 2**12)
        self.assertEqual(gen(b'localhost').cipher_suites[0], 49195)

class TestExtendWithExtToSize(unittest.TestCase):
    def test_with_small_hello(self):
        gen = Firefox_42()

        self.assertLess(len(gen(b'localhost').write()), 2**10)

        gen = extend_with_ext_to_size(gen, 2**12)

        self.assertEqual(len(gen(b'localhost').write()), 2**12)
