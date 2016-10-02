# Copyright (c) 2016 Hubert Kario
# Released under the Mozilla Public License 2.0

"""Classes used for scanning servers and getting their responses."""

import socket

from .constants import CipherSuite, HandshakeType
from .messages import Certificate, ServerHello, Message, NewSessionTicket, \
        CertificateStatus, ServerKeyExchange
from tlslite.constants import CertificateType, ContentType
from tlslite.messages import \
        CertificateRequest, NextProtocol, ServerHelloDone, Alert
from tlslite.defragmenter import Defragmenter
from tlslite.messagesocket import MessageSocket
from tlslite.errors import TLSAbruptCloseError, TLSIllegalParameterException


class HandshakeParser(object):
    """Inteligent parser for handshake messages."""

    def __init__(self, version=(3, 1),
                 cipher_suite=CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                 certificate_type=CertificateType.x509):
        """Initialize parser object."""
        self.version = version
        self.cipher_suite = cipher_suite
        self.certificate_type = certificate_type

    def parse(self, parser):
        """Parse a handshake message."""
        hs_type = parser.get(1)
        if hs_type == HandshakeType.server_hello:
            msg = ServerHello().parse(parser)
            self.version = msg.server_version
            self.cipher_suite = msg.cipher_suite
            self.certificate_type = msg.certificate_type
            return msg
        elif hs_type == HandshakeType.certificate:
            msg = Certificate(self.certificate_type)
        elif hs_type == HandshakeType.server_key_exchange:
            msg = ServerKeyExchange(self.cipher_suite, self.version)
        elif hs_type == HandshakeType.certificate_request:
            msg = CertificateRequest(self.version)
        elif hs_type == HandshakeType.next_protocol:
            msg = NextProtocol().parse(parser)
        elif hs_type == HandshakeType.server_hello_done:
            msg = ServerHelloDone()
        elif hs_type == HandshakeType.session_ticket:
            msg = NewSessionTicket()
        elif hs_type == HandshakeType.certificate_status:
            msg = CertificateStatus()
        else:
            raise ValueError("Unknown handshake type: {0}".format(hs_type))

        # don't abort when we can't parse a message, save it as unparsed
        try:
            msg.parse(parser)
        except SyntaxError:
            msg = Message(ContentType.handshake, parser.bytes)
        return msg


class Scanner(object):
    """Helper class for scanning a host and returning serialised responses."""

    def __init__(self, hello_gen, host, port=443, hostname=None):
        """Initialize scanner."""
        self.host = host
        self.hello_gen = hello_gen
        self.port = port
        self.hostname = hostname

    def scan(self):
        """Perform a scan on server."""
        defragger = Defragmenter()
        defragger.addStaticSize(ContentType.change_cipher_spec, 1)
        defragger.addStaticSize(ContentType.alert, 2)
        defragger.addDynamicSize(ContentType.handshake, 1, 3)

        try:
            raw_sock = socket.create_connection((self.host, self.port), 5)
        except socket.error as e:
            return [e]

        sock = MessageSocket(raw_sock, defragger)

        if self.hostname is not None:
            client_hello = self.hello_gen(bytearray(self.hostname,
                                                    'utf-8'))
        else:
            client_hello = self.hello_gen(None)

        # record layer version - TLSv1.x
        # use the version from configuration, if present, or default to the
        # RFC recommended (3, 1) for TLS and (3, 0) for SSLv3
        if hasattr(client_hello, 'record_version'):
            sock.version = client_hello.record_version
        elif hasattr(self.hello_gen, 'record_version'):
            sock.version = self.hello_gen.record_version
        elif client_hello.client_version > (3, 1):  # TLS1.0
            sock.version = (3, 1)
        else:
            sock.version = client_hello.client_version

        # we don't want to send invalid messages (SSLv2 hello in SSL record
        # layer), so set the record layer version to SSLv2 if the hello is
        # of SSLv2 format
        if client_hello.ssl2:
            sock.version = (0, 2)

        # save the record version used in the end for later analysis
        client_hello.record_version = sock.version

        messages = [client_hello]

        handshake_parser = HandshakeParser()

        try:
            sock.sendMessageBlocking(client_hello)
        except socket.error as e:
            messages.append(e)
            return messages
        except TLSAbruptCloseError as e:
            sock.sock.close()
            messages.append(e)
            return messages

        # get all the server messages that affect connection, abort as soon
        # as they've been read
        try:
            while True:
                header, parser = sock.recvMessageBlocking()

                if header.type == ContentType.alert:
                    alert = Alert()
                    alert.parse(parser)
                    alert.record_version = header.version
                    messages += [alert]
                elif header.type == ContentType.handshake:
                    msg = handshake_parser.parse(parser)
                    msg.record_version = header.version
                    messages += [msg]
                    if isinstance(msg, ServerHelloDone):
                        return messages
                else:
                    raise TypeError("Unknown content type: {0}"
                                    .format(header.type))
        except (TLSAbruptCloseError, TLSIllegalParameterException,
                ValueError, TypeError, socket.error, SyntaxError) as e:
            messages += [e]
            return messages
        finally:
            try:
                sock.sock.close()
            except (socket.error, OSError):
                pass
