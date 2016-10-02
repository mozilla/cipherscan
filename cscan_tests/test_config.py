# Copyright (c) 2015 Hubert Kario
# Released under Mozilla Public License Version 2.0

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.messages import ClientHello
from tlslite.extensions import SNIExtension, SupportedGroupsExtension, \
        ECPointFormatsExtension, NPNExtension, SignatureAlgorithmsExtension
from tlslite.utils.codec import Parser
from cscan.config import Firefox_42, Xmas_tree, Firefox_46
from cscan.extensions import RenegotiationExtension
from cscan.constants import ExtensionType

class TestFirefox(unittest.TestCase):
    def test_firefox_42(self):
        gen = Firefox_42()
        ch = gen(bytearray(b'example.com'))

        self.assertIsNotNone(ch)
        self.assertIsInstance(ch, ClientHello)
        self.assertEqual(len(ch.write()), 176)
        self.assertEqual(ch.client_version, (3, 3))
        self.assertEqual(gen.record_version, (3, 1))
        self.assertEqual(len(ch.cipher_suites), 11)
        self.assertIsInstance(ch.extensions[0], SNIExtension)
        self.assertEqual(ch.extensions[1].extType,
                         ExtensionType.renegotiation_info)
        self.assertIsInstance(ch.extensions[2],
                              SupportedGroupsExtension)
        self.assertIsInstance(ch.extensions[3],
                              ECPointFormatsExtension)
        self.assertEqual(ch.extensions[4].extType,
                         ExtensionType.session_ticket)
        # bug in tlslite-ng, removes NPN extensions from provided extensions
        #self.assertIsInstance(ch.extensions[5],
        #                      NPNExtension)
        self.assertEqual(ch.extensions[5].extType,
                         ExtensionType.alpn)
        self.assertEqual(ch.extensions[6].extType,
                         ExtensionType.status_request)
        self.assertIsInstance(ch.extensions[7],
                              SignatureAlgorithmsExtension)
        self.assertEqual(ch.compression_methods, [0])

    def test_firefox_46(self):
        gen = Firefox_46()
        ch = gen(bytearray(b'example.com'))

        self.assertIsNotNone(ch)
        self.assertIsInstance(ch, ClientHello)
        self.assertEqual(len(ch.write()), 180)
        self.assertEqual(ch.client_version, (3, 3))
        self.assertEqual(gen.record_version, (3, 1))
        self.assertEqual(len(ch.cipher_suites), 11)
        self.assertIsInstance(ch.extensions[0], SNIExtension)
        self.assertEqual(ch.extensions[1].extType,
                         ExtensionType.extended_master_secret)
        self.assertEqual(ch.extensions[2].extType,
                         ExtensionType.renegotiation_info)
        self.assertIsInstance(ch.extensions[3],
                              SupportedGroupsExtension)
        self.assertIsInstance(ch.extensions[4],
                              ECPointFormatsExtension)
        self.assertEqual(ch.extensions[5].extType,
                         ExtensionType.session_ticket)
        # bug in tlslite-ng, removes NPN extensions from provided extensions
        #self.assertIsInstance(ch.extensions[6],
        #                      NPNExtension)
        self.assertEqual(ch.extensions[6].extType,
                         ExtensionType.alpn)
        self.assertEqual(ch.extensions[7].extType,
                         ExtensionType.status_request)
        self.assertIsInstance(ch.extensions[8],
                              SignatureAlgorithmsExtension)
        self.assertEqual(ch.compression_methods, [0])

class TestXmasTree(unittest.TestCase):
    def test_xmas_tree_tls_1_3(self):
        ch = Xmas_tree()(bytearray(b'example.com'))

        self.assertIsNotNone(ch)
        self.assertIsInstance(ch, ClientHello)
        self.assertEqual(len(ch.write()), 2792)

    def test_xmas_tree_tls_1_3_parse(self):
        ch = Xmas_tree()(bytearray(b'example.com'))

        parser = Parser(ch.write()[1:])

        client_hello = ClientHello()
        client_hello.parse(parser)


if __name__ == "__main__":
    unittest.main()
