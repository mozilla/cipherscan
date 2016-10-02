# Copyright (c) 2015 Hubert Kario
# Released under Mozilla Public License Version 2.0

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.utils.codec import Parser
from cscan.extensions import KeyShareExtension
from cscan.constants import GroupName

class TestKeyShareExtension(unittest.TestCase):
    def test___init__(self):
        ext = KeyShareExtension()

        self.assertIsNotNone(ext)

    def test_create(self):
        ext = KeyShareExtension()

        ext.create([(1, bytearray(b'\x12')),
                    (2, bytearray(b'\x33'))])

        self.assertEqual(ext.client_shares, [(1, bytearray(b'\x12')),
                                             (2, bytearray(b'\x33'))])

    def test_write(self):
        ext = KeyShareExtension()

        ext.create([(GroupName.secp256r1, bytearray(b'\xff\xfa')),
                    (GroupName.ffdhe2048, bytearray(b'\xaf\xaa'))])

        data = ext.write()

        self.assertEqual(data, bytearray(
            b'\x00\x2a\x00\x0d'
            b'\x00\x0b'
            b'\x00\x17\x02\xff\xfa'
            b'\x01\x00\x00\x02\xaf\xaa'))

    def test_write_with_no_data(self):
        ext = KeyShareExtension()

        data = ext.write()

        self.assertEqual(data, bytearray(b'\x00\x2a\x00\x00'))

    def test_parse(self):
        parser = Parser(bytearray(
            #b'\x00\x2a\x00\x0d'
            b'\x00\x0b'
            b'\x00\x17\x02\xff\xfa'
            b'\x01\x00\x00\x02\xaf\xaa'))

        ext = KeyShareExtension()
        ext.parse(parser)

        self.assertEqual(ext.client_shares,
                         [(GroupName.secp256r1, bytearray(b'\xff\xfa')),
                          (GroupName.ffdhe2048, bytearray(b'\xaf\xaa'))])

    def test_parse_with_no_data(self):
        parser = Parser(bytearray())

        ext = KeyShareExtension()
        ext.parse(parser)

        self.assertIsNone(ext.client_shares)

    def test___repr__(self):
        ext = KeyShareExtension()
        ext.create([(1, bytearray(b'\xff'))])

        self.assertEqual("KeyShareExtension([(1, bytearray(b\'\\xff\'))])",
                         repr(ext))
