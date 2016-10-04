# Copyright 2016(c) Hubert Kario
# This work is released under the Mozilla Public License Version 2.0

"""Extra TLS extensions."""

import tlslite.extensions
from tlslite.utils.codec import Writer
from tlslite.utils.compat import b2a_hex
from .constants import ExtensionType, GroupName
import .messages

# make TLSExtensions hashable (__eq__ is already defined in base class)
tlslite.extensions.TLSExtension.__hash__ = lambda self: hash(self.extType) ^ \
        hash(bytes(self.extData))


class RenegotiationExtension(tlslite.extensions.TLSExtension):
    """Secure Renegotiation extension RFC 5746."""

    def __init__(self):
        """Initialize secure renegotiation extension."""
        super(RenegotiationExtension, self).__init__(
            extType=ExtensionType.renegotiation_info)
        self.renegotiated_connection = None

    def create(self, data):
        """Set the value of the Finished message."""
        self.renegotiated_connection = data

    @property
    def extData(self):
        """Serialise the extension."""
        if self.renegotiated_connection is None:
            return bytearray(0)

        writer = Writer()
        writer.addVarSeq(self.renegotiated_connection, 1, 1)
        return writer.bytes

    def parse(self, parser):
        """Deserialise the extension from binary data."""
        if parser.getRemainingLength() == 0:
            self.renegotiated_connection = None
            return

        self.renegotiated_connection = parser.getVarBytes(1)
        return self

    def __repr__(self):
        """Human readable representation of extension."""
        return "RenegotiationExtension(renegotiated_connection={0!r})"\
               .format(self.renegotiated_connection)

    def __format__(self, formatstr):
        """Formatted representation of extension."""
        data = messages.format_bytearray(self.renegotiated_connection,
                                         formatstr)
        return "RenegotiationExtension(renegotiated_connection={0})"\
               .format(data)

tlslite.extensions.TLSExtension._universalExtensions[
        ExtensionType.renegotiation_info] = RenegotiationExtension


class SessionTicketExtension(tlslite.extensions.TLSExtension):
    """Session Ticket extension (a.k.a. OCSP staple)."""

    def __init__(self):
        """Create Session Ticket extension."""
        super(SessionTicketExtension, self).__init__(
                extType=ExtensionType.session_ticket)
        self.data = bytearray(0)

    def parse(self, parser):
        """Deserialise the extension from binary data."""
        self.data = parser.bytes
        return self

    def __format__(self, formatstr):
        """Print extension data in human-readable form."""
        data = messages.format_bytearray(self.data, formatstr)
        return "SessionTicketExtension(data={0})".format(data)

tlslite.extensions.TLSExtension._universalExtensions[
        ExtensionType.session_ticket] = SessionTicketExtension


class ServerStatusRequestExtension(tlslite.extensions.TLSExtension):
    """Server Status Request extension."""

    def __init__(self):
        """Create server status request extension."""
        super(ServerStatusRequestExtension, self).__init__(
                extType=ExtensionType.status_request)

    def parse(self, parser):
        """Deserialise the extension from binary data."""
        if parser.getRemainingLength() != 0:
            raise SyntaxError()  # FIXME
        return self

    def __repr__(self):
        """Human readable representation of the object."""
        return "ServerStatusRequestExtension()"

tlslite.extensions.TLSExtension._serverExtensions[
        ExtensionType.status_request] = ServerStatusRequestExtension


class KeyShareExtension(tlslite.extensions.TLSExtension):
    """TLS1.3 extension for handling key negotiation."""

    def __init__(self):
        """Create key share extension object."""
        super(KeyShareExtension, self).__init__(
                extType=ExtensionType.key_share)
        self.client_shares = None

    def create(self, shares):
        """
        Set the list of key shares to send.

        @type shares: list of tuples
        @param shares: a list of tuples where the first element is a NamedGroup
        ID while the second element in a tuple is an opaque bytearray encoding
        of the key share.
        """
        self.client_shares = shares
        return self

    @property
    def extData(self):
        """Serialise the extension."""
        if self.client_shares is None:
            return bytearray(0)

        writer = Writer()
        for group_id, share in self.client_shares:
            writer.add(group_id, 2)
            if group_id in GroupName.allFF:
                share_length_length = 2
            else:
                share_length_length = 1
            writer.addVarSeq(share, 1, share_length_length)
        ext_writer = Writer()
        ext_writer.add(len(writer.bytes), 2)
        ext_writer.bytes += writer.bytes
        return ext_writer.bytes

    def parse(self, parser):
        """Deserialise the extension."""
        if parser.getRemainingLength() == 0:
            self.client_shares = None
            return

        self.client_shares = []

        parser.startLengthCheck(2)
        while not parser.atLengthCheck():
            group_id = parser.get(2)
            if group_id in GroupName.allFF:
                share_length_length = 2
            else:
                share_length_length = 1
            share = parser.getVarBytes(share_length_length)
            self.client_shares.append((group_id, share))

        return self

    def __repr__(self):
        """Human readble representation of extension."""
        return "KeyShareExtension({0!r})".format(self.client_shares)

    def __format__(self, formatstr):
        """Formattable representation of extension."""
        if self.client_shares is None:
            return "KeyShareExtension(None)"

        verbose = ""
        hexlify = False
        if 'v' in formatstr:
            verbose = "GroupName."
        if 'h' in formatstr:
            hexlify = True

        shares = []
        for group_id, share in self.client_shares:
            if hexlify:
                share = b2a_hex(share)
            else:
                share = repr(share)
            shares += ["({0}{1}, {2})".format(verbose,
                                              GroupName.toStr(group_id),
                                              share)]
        return "KeyShareExtension([" + ",".join(shares) + "])"

tlslite.extensions.TLSExtension._universalExtensions[
        ExtensionType.key_share] = KeyShareExtension
