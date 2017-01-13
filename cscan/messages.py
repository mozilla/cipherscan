# Copyright (c) 2016 Hubert Kario
# Released under Mozilla Public License 2.0

"""Extensions and modification of the tlslite-ng messages classes."""

import tlslite.messages as messages
from tlslite.utils.compat import b2a_hex
from tlslite.constants import ContentType, CertificateType, ECCurveType, \
        HashAlgorithm, SignatureAlgorithm
from tlslite.x509certchain import X509CertChain
from tlslite.utils.cryptomath import secureHash
from .constants import HandshakeType, CipherSuite, GroupName

# gotta go fast
# comparing client hello's using ClientHello.write() is painfully slow
# monkey patch in faster compare methods


def __CH_eq_fun(self, other):
    """
    Check if the other is equal to the object.

    always returns false if other is not a ClientHello object
    """
    if not isinstance(other, messages.ClientHello):
        return False

    return self.ssl2 == other.ssl2 and \
        self.client_version == other.client_version and \
        self.random == other.random and \
        self.session_id == other.session_id and \
        self.cipher_suites == other.cipher_suites and \
        self.compression_methods == other.compression_methods and \
        self.extensions == other.extensions

messages.ClientHello.__eq__ = __CH_eq_fun


def __CH_ne_fun(self, other):
    """
    Check if the other is not equal to the object.

    always returns true if other is not a ClientHello object
    """
    return not self.__eq__(other)

messages.ClientHello.__ne__ = __CH_ne_fun


def format_bytearray(byte_array, formatstr):
    """Format method for bytearrays."""
    if 'x' in formatstr:
        return b2a_hex(byte_array)
    else:
        return repr(byte_array)


def format_array(array, formatstr):
    """Return string representation of array while formatting elements."""
    if array is None:
        return "None"
    else:
        str_array = []
        for elem in array:
            if elem.__class__.__format__ is not object.__format__:
                str_array += ["{0:{1}}".format(elem, formatstr)]
            else:
                str_array += [repr(elem)]
        return "[" + ", ".join(str_array) + "]"


class ServerHello(messages.ServerHello):
    """Class with enhanced human-readable serialisation."""

    def __format__(self, formatstr):
        """Return human readable representation of the object."""
        extensions = format_array(self.extensions, formatstr)
        random = format_bytearray(self.random, formatstr)
        session_id = format_bytearray(self.session_id, formatstr)
        cipher_suite = CipherSuite.ietfNames.get(self.cipher_suite,
                                                 self.cipher_suite)

        if 'v' in formatstr:
            cipher_suite = "CipherSuite.{0}".format(cipher_suite)

        # TODO cipher_suites (including verbose)
        # TODO compression_method (including verbose)
        return ("ServerHello(server_version=({0[0]}, {0[1]}), random={1}, "
                "session_id={2!r}, cipher_suite={3}, compression_method={4}, "
                "_tack_ext={5}, extensions={6})").format(
                self.server_version, random, session_id,
                cipher_suite, self.compression_method, self._tack_ext,
                extensions)


class Certificate(messages.Certificate):
    """Class with more robust certificate parsing and serialisation."""

    def parse(self, parser):
        """Deserialise the object from binary data."""
        index = parser.index
        try:
            return super(Certificate, self).parse(parser)
        except (AssertionError, SyntaxError):
            pass
        parser.index = index
        parser.startLengthCheck(3)
        if self.certificateType == CertificateType.x509:
            chainLength = parser.get(3)
            index = 0
            certificate_list = []
            while index != chainLength:
                certBytes = parser.getVarBytes(3)
                certificate_list.append(certBytes)
                index += len(certBytes)+3
            if certificate_list:
                self.certChain = certificate_list
        else:
            raise AssertionError()

        parser.stopLengthCheck()
        return self

    def __format__(self, formatstr):
        """Advanced formatting for messages."""
        hexify = False
        verbose = False
        digest = False
        if 'h' in formatstr:
            hexify = True
        if 'v' in formatstr:
            verbose = True
        if 'm' in formatstr:
            digest = True

        if self.certChain is None:
            cert_list = None
        else:
            if isinstance(self.certChain, X509CertChain):
                cert_list = [cert.bytes for cert in self.certChain.x509List]
            else:
                cert_list = self.certChain

            if digest:
                cert_list = "[" + ", ".join(b2a_hex(secureHash(cert, 'sha256'))
                                            for cert in cert_list) + "]"
            else:
                cert_list = [repr(cert) for cert in cert_list]

        return "Certificate({0})".format(cert_list)


class NewSessionTicket(messages.HandshakeMsg):
    """Class for handling the Session Tickets from RFC 5077."""

    def __init__(self):
        """Initilize new sesion ticket message object."""
        super(NewSessionTicket, self).__init__(HandshakeType.session_ticket)
        self.ticket_lifetime_hintt = 0
        self.ticket = None

    def parse(self, parser):
        """Parse the object from on-the-wire data."""
        self.ticket_lifetime_hint = parser.get(4)
        self.ticket = parser.getVarBytes(2)
        return self

    def __format__(self, formatstr):
        """Return human-readable representation of the object."""
        ticket = format_bytearray(self.ticket, formatstr)
        return "NewSessionTicket(ticket_lifetime_hint={0}, ticket={1})"\
               .format(self.ticket_lifetime_hintt, ticket)


class CertificateStatus(messages.HandshakeMsg):
    """Class for handling the CertificateStatus OCSP staples from RFC 4366."""

    def __init__(self):
        """Create a certificate status message handling object."""
        super(CertificateStatus, self).__init__(
                HandshakeType.certificate_status)
        self.status_type = 0
        self.response = None

    def parse(self, parser):
        """Deserialise certificate status message from binary data."""
        parser.startLengthCheck(3)
        self.status_type = parser.get(1)
        if self.status_type == 1:  # FIXME, create registry
            self.response = parser.getVarBytes(3)
        else:
            raise SyntaxError()  # FIXME, use sane-er type
        parser.stopLengthCheck()
        return self

    def __format__(self, formatstr):
        """Return human-readable representation of certificate status."""
        response = format_bytearray(self.response, formatstr)
        return "CertificateStatus(status_type={0}, response={1})"\
               .format(self.status_type, response)


class Message(messages.Message):
    """Message class with more robust formatting capability."""

    def __format__(self, formatstr):
        """Advanced formatting for messages."""
        hexify = False
        verbose = ""
        if 'h' in formatstr:
            hexify = True
        if 'v' in formatstr:
            verbose = "ContentType."

        if hexify:
            data = b2a_hex(self.data)
        else:
            data = repr(self.data)

        return "Message(contentType={0}{1}, data={2})"\
               .format(verbose, ContentType.toStr(self.contentType), data)


class ServerKeyExchange(messages.ServerKeyExchange):
    """ServerKeyExchange class with more robust formatting capability."""

    def parse(self, parser):
        """more robust parser for SKE"""
        try:
            super(ServerKeyExchange, self).parse(parser)
        except AssertionError:
            pass
        return self

    def __format__(self, formatstr):
        """Return human-readable representation of the object."""
        if 'v' in formatstr:
            verbose = "CipherSuite."
        else:
            verbose = ""

        ret = "ServerKeyExchange(cipherSuite={0}{1}, version={2}"\
              .format(verbose, CipherSuite.ietfNames[self.cipherSuite],
                      self.version)
        if self.srp_N:
            ret += ", srp_N={0}, srp_g={1}, srp_s={2}, srp_B={3}"\
                   .format(self.srp_N, self.srp_g, self.srp_s, self.srp_B)
        if self.dh_p:
            ret += ", dh_p={0}, dh_g={1}, dh_Ys={2}"\
                   .format(self.dh_p, self.dh_g, self.dh_Ys)
        if self.ecdh_Ys:
            ecdh_Ys = format_bytearray(self.ecdh_Ys, formatstr)
            ret += ", curve_type={0}, named_curve={1}, ecdh_Ys={2}"\
                   .format(ECCurveType.toStr(self.curve_type),
                           GroupName.toStr(self.named_curve), ecdh_Ys)
        if self.signAlg:
            ret += ", hashAlg={0}, signAlg={1}"\
                   .format(HashAlgorithm.toStr(self.hashAlg),
                           SignatureAlgorithm.toStr(self.signAlg))
        if self.signature:
            ret += ", signature={0}"\
                   .format(format_bytearray(self.signature, formatstr))

        return ret + ")"
