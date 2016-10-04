# Copyright (c) 2016 Hubert Kario <hkario@redhat.com>
# Released under Mozilla Public License Version 2.0

"""Typical Client Hello messages sent by different clients."""

import random
from tlslite.messages import ClientHello
from tlslite.constants import \
        ECPointFormat, HashAlgorithm, SignatureAlgorithm
from tlslite.extensions import SNIExtension, SupportedGroupsExtension, \
        TLSExtension, SignatureAlgorithmsExtension, NPNExtension, \
        ECPointFormatsExtension
from tlslite.utils.cryptomath import numberToByteArray
from .constants import CipherSuite, ExtensionType, GroupName


class HelloConfig(object):
    """Base object for all Client Hello configurations."""

    def __init__(self):
        """Initialize object with default settings."""
        self._name = None
        self.modifications = []
        self.callbacks = []
        self.version = (3, 3)
        self.record_version = (3, 0)
        self.ciphers = []
        self.extensions = None
        self.random = None
        self.session_id = bytearray(0)
        self.compression_methods = [0]
        self.ssl2 = False

    @property
    def name(self):
        """Return the name of config with all the modifications applied."""
        if self.modifications:
            return "{0} ({1})".format(self._name,
                                      ", ".join(self.modifications))
        else:
            return self._name

    @name.setter
    def name(self, value):
        """Set the base name of the configuration."""
        self._name = value

    def __call__(self, hostname):
        """Generate a client hello object, use hostname in SNI extension."""
        # SNI is special in that we don't want to send it if it is empty
        if self.extensions:
            sni = next((x for x in self.extensions
                        if isinstance(x, SNIExtension)),
                       None)
            if sni:
                if hostname is not None:
                    if sni.serverNames is None:
                        sni.serverNames = []
                    sni.hostNames = [hostname]
                else:
                    # but if we were not provided with a host name, we want
                    # to remove empty extension
                    if sni.serverNames is None:
                        self.extensions = [x for x in self.extensions
                                           if not isinstance(x, SNIExtension)]

        if self.random:
            rand = self.random
        else:
            # we're not doing any crypto with it, just need "something"
            # TODO: place unix time at the beginning
            rand = numberToByteArray(random.getrandbits(256), 32)

        ch = ClientHello(self.ssl2).create(self.version, rand, self.session_id,
                                           self.ciphers,
                                           extensions=self.extensions)
        ch.compression_methods = self.compression_methods
        for cb in self.callbacks:
            ch = cb(ch)
        return ch


class Firefox_42(HelloConfig):
    """Create Client Hello like Firefox 42."""

    def __init__(self):
        """Set the configuration to Firefox 42."""
        super(Firefox_42, self).__init__()
        self._name = "Firefox 42"
        self.version = (3, 3)
        self.record_version = (3, 1)
        self.ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA]
        ext = self.extensions = []
        ext.append(SNIExtension())
        ext.append(TLSExtension(extType=ExtensionType.renegotiation_info)
                   .create(bytearray(1)))
        ext.append(SupportedGroupsExtension().create([GroupName.secp256r1,
                                                      GroupName.secp384r1,
                                                      GroupName.secp521r1]))
        ext.append(ECPointFormatsExtension()
                   .create([ECPointFormat.uncompressed]))
        ext.append(TLSExtension(extType=ExtensionType.session_ticket))
        ext.append(NPNExtension())
        ext.append(TLSExtension(extType=ExtensionType.alpn)
                   .create(bytearray(b'\x00\x15' +
                                     b'\x02' + b'h2' +
                                     b'\x08' + b'spdy/3.1' +
                                     b'\x08' + b'http/1.1')))
        ext.append(TLSExtension(extType=ExtensionType.status_request)
                   .create(bytearray(b'\x01' +
                                     b'\x00\x00' +
                                     b'\x00\x00')))
        sig_algs = []
        for alg in ['sha256', 'sha384', 'sha512', 'sha1']:
            sig_algs.append((getattr(HashAlgorithm, alg),
                             SignatureAlgorithm.rsa))
        for alg in ['sha256', 'sha384', 'sha512', 'sha1']:
            sig_algs.append((getattr(HashAlgorithm, alg),
                             SignatureAlgorithm.ecdsa))
        for alg in ['sha256', 'sha1']:
            sig_algs.append((getattr(HashAlgorithm, alg),
                             SignatureAlgorithm.dsa))
        ext.append(SignatureAlgorithmsExtension()
                   .create(sig_algs))
