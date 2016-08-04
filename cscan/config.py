# Copyright (c) 2016 Hubert Kario <hkario@redhat.com>
# Released under Mozilla Public License Version 2.0

"""Typical Client Hello messages sent by different clients."""

import random
from tlslite.messages import ClientHello
from tlslite.constants import \
        ECPointFormat, HashAlgorithm, SignatureAlgorithm
from tlslite.mathtls import goodGroupParameters
from tlslite.extensions import SNIExtension, SupportedGroupsExtension, \
        TLSExtension, SignatureAlgorithmsExtension, NPNExtension, \
        ECPointFormatsExtension, PaddingExtension
from tlslite.utils.cryptomath import numberToByteArray
from tlslite.utils.ecc import getCurveByName, encodeX962Point
from tlslite.utils.cryptomath import powMod
from .constants import CipherSuite, ExtensionType, GroupName
from .extensions import KeyShareExtension

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


class Firefox_46(HelloConfig):
    """Create ClientHello like Firefox 46"""
    # verified by packet capture
    def __init__(self):
        super(Firefox_46, self).__init__()
        self._name = "Firefox 46"
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
        ext.append(TLSExtension(extType=ExtensionType.extended_master_secret))
        ext.append(TLSExtension(extType=ExtensionType.renegotiation_info)
                   .create(bytearray(1)))
        ext.append(SupportedGroupsExtension().create([GroupName.secp256r1,
                                                      GroupName.secp384r1,
                                                      GroupName.secp521r1]))
        ext.append(ECPointFormatsExtension().create([ECPointFormat.uncompressed]))
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

_ec_precomputed = {
        'secp256r1' : [
            bytearray(b'\x04\x85\x96\xe5\xa1\x92\x99\xf8\xb1\xb1}\xcd\xdc\x1c^\xfd05\xa1\xe1\xd3\xd0\x87s\xb1\xd8>\x00TX\xac\x86\xe1\xa3\xb0c~\x85\x8d&\xaf"X\xb5\x9cf\x8d\xf4\xf5d\xd7u\'&]\xbe\xe3\x83]ul\xff\x86e\x89'),
            bytearray(b'\x04\xa89\xfc\xb2r\xf3\x03p6\xca\xb6\xe2\xb1t2\t\x8b\xb2\x89\xce\x8f\x84\r\x8b\x1b\r\\\r/\xcd\xabn\xb6WE\xb7\x9a\xba\r\xdb\x03\xc3\x9c\xd9N\x19\x03[\xe0\nK\xf3\xfb\x00\xbe]d\x96e\xf2\xde\x94\td'),
            bytearray(b'\x04\xaa\xf1Q\xfb\xf1\x95\x03\xaa\x8d\x8c\xefB\x8c;\x04u\xdaG\xee\xe5\xd9`J\xe3\x90\xc3T\x02\xe7\x80\x9b\x0f,bi4m2\n\xffD\x9b\xb68\x10\xa3\xbdd]\x05\xa3\x81\xfe\x97J\x9aY\x0e\xe3\x1b\xad\xe4\x84\xbd'),
            bytearray(b'\x04\x17\xf9K\x1b\x95\xd3\xf7\xfc`y\xe7g*A\xeb4!\xbca\xd1)\xa0\x0e\xa88\xbd\xb0\xd6\x9a\x97\x95\xa1R2\xcc]$[\xc1\x90T\x83Lu\xbb%I\x81\x8a\x11\x0c\x01\x07)"\x80\xbb\xbaS\xa5`r\x91\xe6'),
            bytearray(b"\x04xGX\x06\xb2N\xe2\x9f\xfc\xdc}\xd2\xdbU\x9a$\xb6\xbc`\xb6\xec\xaa\xad(\xa4\x7fwU\xcfK/T\xea\xa5\xc2Y\xf7<\xfe\xa9\xaf\xa2f7\xa2\'/\xfd\x18\xae\x1e\xc0,\xa5cd\x8d2\x98\xeeA#\x13\x9c"),
            bytearray(b'\x04\x14\xf0\xf5_\xa1\xf6\xa5\x1c\xf4%\x17\xc4\x86uE|\xc3#\x11\x9b\xf8\xf2\xcc\xc8F/\xcb\xc46,\x81+@\xbeS\x93\xa59\xae\xc8\xe9 {\r\xdfE j!\xa7\xef\x85\x04\xa0\x9bI\xbbiC\x9c#II\xb2')],
        'secp384r1' : [
            bytearray(b'\x04*\x9c\x14\xfe!_\xea\xa7\xef\x8aR\xd7\x9d\xab\xc3fU6)\x8b\xce\x935q\x92l\xbc\xb84\x96$\xf0\x86\x05\x85\xaaEq\xca0\x99\xf6c\xf2+=\xc9!Ms%z\xf7\x98\x1auCOb\xcc\xdc\x89\x1d\x97\xa7y\xe0\x8e\xea/\x80brj\xd7\x1b\x17\x89<\xe5\xba\xa3*\x0c\xb5\r\xde}\xa7{\x94\x9f\x81\xb3:\x92'),
            bytearray(b"\x04\x9b]\xfap\xf5R\xefCv\x95\xc4c\xea\xee\xe1i\xf80\x97\x08\xdb\xe7\x83a\x8f~`\xd7`>A\x8aS6\x82\'\xd6711\x9b,+\xc9\xbb\xa7\xa3E\xe3\xfb\x1a\xa2\x83\xac\xf8\x0eV\x93y\xb2w\xe5\xf5hQ3H\xa0\xa9\x8d\xfdg\xe9\xac\x12\xcd%(bY\xc5+\x98o\xb5D1\xcbu\x7f\t\x8f\xfe\xfa\x16q"),
            bytearray(b'\x04@\'b\'{\x15H\xb0\x9c?\xe5dg\xbf\xe4\'\xe1D\xf7FIs\xb9\x153\x87x\xcb\xb7\xf6b\x9b\xe5\x10_\xfc%Z\x87\xa5\xae(\x13\xb1*]_g\xd4\xeaeH\x83\xed\xa0N\x82Mqz;\xbba\x0f\xf6\x9c\x08"\xca\x00\x8fq\xc5\xc7\t{\xf1l_h\x05\xec\x9a\x19N\x98+%=?\x14\xbf0\x94\x13"'),
            bytearray(b"\x04pM\xfe\xf0+h\xe3\x9d\xda\xe1x1\x02}\xa4\xa2\x83\'\xfem\x1a;\xbf\x10\xd7\xb2\xd9I\x06-\x9fY\xa3k9\xc4\xc8\xda\x1e>G\xaf\xcb|\x01\xd6j\xff|\xe0>\x81I\x8b\x03\xd3\xf8\xc9|\xab&w\xf8\x1b\x9a\x98\xb1CXAU\t\x03\xd6\xcf\xa0L\xd1B \x13Mr\xbe\x8b\xe6}\xf2\xb2oc\x98A\x94\x9eX"),
            bytearray(b'\x04\x1a[X\x13\x17"^\x02\x19d\xc4\xec\x14\xea<\x8c\xd2f\x95\xb4b\xdc\xbbG;pq\x9a^\xf8\xd0\xe7\x99Ofk\x1e#\x8dZ\xcb\xbf\x1e=p\xaa\xe5\x92\xda^\xb2\x86\xdf\xf8(\xfcIc\xde\xcempP\x82\xcd\x88\xe3\x87\xd1\x8b\xac\xe5\x19\xd4)\ndPX\\)\xf7\x1c\xdef\x0e` \x13\xa1\xa8YSun4'),
            bytearray(b"\x04\xce\xbe\xb9{$#\x03c\xdemi\xf0\xec\x07]Q8^\x8b\xdd,)~\x972]cI\xbe\xc9\x8b\xa0\xd7\xc7\x96H\xa4\xea\xb2\x86%\xee\xb2\xc8\x08\x1d\xa4\xb9\xc5Bc \xac-;J{\x10\xafh\xceU*+h\xda&7\'\x15<x\xa8\xb9\xbecR\x97\xff<\xb2\xba\x92!\xc6|\xb1\xb5\x01\xb5c\xc9|\xe7\xbd\x01")],
        'secp521r1' : [
            bytearray(b"\x04\x01\xf9\xe3\x88\xcdU\xeb\xda.3\x8b\xf8\xc2\x82M\xd9\xf1@\x9d\xa6\xee\xa4\xc7\x82\xbf\x81S\xce\xedQ\xb4o,(>\xb7d5\xfd\x94\x86\xd3\xe8=\xcc\xbf\x8d\x07\x17\xc9(\x17U@gH\x8d]\xc5\xe2\xe2;.S\xf9\xa1\x00\xc2\xb5\xb7\'\x05f\xe6\xf3\xf7Za\xa1\xa4\x9209\xf3I\xe3\xdd%\xd1\x8a\x82\n4Z\xa1ol?l(\x939_+(\x1c\xca\xa4\xc3\xdb\x01\x19\xc5\xb4\xfc\xb7\xa8\xa4\xd3\x14x\x0c\x1f\x91\xd1!5\x1a\xb0\x0b\xa7\xe9"),
            bytearray(b'\x04\x01\xban\x80\x85\xe8\xc7\xd0r\x17\x84\xea\x16\xc0\xfdM\xde\x98\xfe\x82\xd9\x06{\t\x1f*\xa2(t\xd4\x95y\xb7\x98\xbbP\xf1\xd9_9\xe3\xd3\xf8\xf1\xa9\xec\x1c\xce\xf6\\\xb1\xb6`|\xb9`]Wy\xaf\x99\xfc\xc2\xa5$\xd9\x01\xb5Y\x85\x85.\xc8\x8a\x94\xde\xbc\xe6m/\x04C 6|m\x92\x00\xfan*\x1c\xb7z\xbc\xc4|\xea,/t\xc7,"<R5h\x95\xf9\xc3%\x87\xa6!\x97\xa9\x94\xc7\t=\x1d\x8b,\xb6\xb5\xafF_r\\V'),
            bytearray(b'\x04\x01\xf5?\xbf\x065\x9bB}\xdb\x90\xadD\xd6\xe2?e\xae\xb9\x13\xa8zZ7\xa0\xa3\xf1}b3\\\x08\x81d~V\\;\xd2\x9a\xc9\x93\x84-e\'\x9cy\xc1t\xaa\xce\x0f\x9a\xfdk\x1c9\xf6R\xeb\xa1\xf4kw\x10\x01P)]\xfb\xc7n\xb7\xfe\xd8\xdaO\xc9DK\xbb\xb4/\xfb\x17J\x98\xaen\xd4\x93\x16n\xb1\x95\x94\xe5\xc6\xfd\x0bADj\x0e\xc1\xf5\x81`\xc8\xe9;X\ttr\xb1.\x96f\xe2\xc9^?\xf7r=\xf2"\x9f}<'),
            bytearray(b'\x04\x01g3\xe2\x1f\x8b|$#V\xa0\x05\xd0=\xc6\xdf\xd9\xaf\xf2&\xebEn\xf6?9\xfaQ\xfb\x94\x8be3\x1f\xb3\x91\xa5|3\x981\x8d\x1d\x92QL\xd6\xa3\x80o++9\xaf#cN\xe8\x19O\x84+\x8e\x1cT\xf8\x00\xca\xe2\x01\xbc\xd9\xa4\xccV\xa0\x1d\xb7\xe7\xecm{\xa9<\xc31o&\xfaq\xba\x1av\x80\x1c\x06\xd3\xad\x95-\x9d\x03\x1e\x97}\xd2??\xb8\xb3r\x94\xd1\xba\x9aC\x95\xe2\xab\xd1\xe3V2\x0f\xbe\xce\xdb\xbamT\xf7\xd3'),
            bytearray(b'\x04\x01~\xea\x9a?\xc3[\x99\x8f\xa0z\x1a\x95\xa8T\xd6Y\xc9\x90\xbe\\!\x82\xd2\x04"/\xe7\xf1\xb9,\x7f~\x12\xc3\xe4\xcd\x9f\xf0.!\x1c?2v\x0b\xa7\x04\xe64\x8c\x1a2V\x91\x07\xe2\xc8\x182\xc6\x9b\x9e\xe8\x02\xc1\x00\x05\xfd\xc5\x16S\xa4\x97Ds\x95\xb4Md\xd79\x1cn\xdfLC\'\x02\xcf\x9f\xdb\xa8\xd5\x88\x99\xb3/\xb4M\x8fN\xcf\x81\xeb\x97z\x05\x17\xb4\xcdb\x86\x86\x84\\\xe1Y\x96\xf09\x02\xa79S9\x15\x91\xce\xd84g'),
            bytearray(b'\x04\x01\xbc\xcd7\xb4\x03\xfa.\x0e\x01\xf7\x13\xa4e\xd9\xfd\xcb\xb9\xfb\x8c\xf5\x1e\x1b\xafU\xedN\x00C\xe7b\xcf\x0c\xcd"\x9a\xec\xec\xf6\xce\xbf\x9a\x9d&\x12\x03\x05T,\x98*\xbc0g\xf5\x9e{/B\xdd5dv\xafNs\x01\xe0\x8d\xf9\x8b\x92\xa0\x9f\xf3\xf8oi\xba\xe8(\xc9\xa2R\x8b\xf9C\xa1):A"\xec\x80\xf5\x94\xb2\xd7\x1d\xc0\x9eU\x10\x18\xd9\xc6 i\\0\xb1\xc5\xc1S\xac\x94< \xb1\xe7\xf0L[\x02T\xde\xac0\xb90\xa4\x05')]
        }

def _ec_key_share(name):
    if name in _ec_precomputed:
        return random.choice(_ec_precomputed[name])
    generator = getCurveByName(name).generator
    secret = random.randint(2, generator.order())

    ret = encodeX962Point(generator * secret)
    return ret

_ff_precomputed = {
        'ffdhe8192' : [
            bytearray(b'\xea8\xe0\xccGf\x1c)\xb9\xf2p\x87\\s\xb2\xa2\xa3\xb3F#\x1a\x92@\x92@1]D\x9b\xf4\xb5g\x02\x86M\xa8 *\xa0\xb2P9\xbf!v\xca\xdb\xfb\xaf\xf9\x1fn\x8f.\x1b,\xff8\x04\\Vn\xd3\xcdM\xfa\x10\xfeh\xd7u\xf5j\xf8\xc9\x08F\xe7\x98P\xa4n\xea\xa0\x81W\xf0@4M\\\x84j\x87\x1e\xe37{)\\\xd5\xb3\xcfm-]\xd8\x9d\xc6\x17\xb4,\xe1:\xd6\xbc\xb52Am\xcf\x87\x020\xf0*2\xb4\xc6\x03\xfd\x01\xd6s\xf7\xe9\xf3\x01I\xc2m\xaf\xd6\x98\x9edg\xeax\x14\x0e8V0Je)\xe2j\xcc\x89\xf5K\xc5\xaa\x0c\x08m&0\xda:\x08fZ\xcbh\x1fkY&\xb9\xca\xd7\x7f\xb6w\x1d}Z4T^\x00\x058\x0b\xe3\xcf\x10\xdb\x1a\x10\xfe\xce\xd1f\xeaT\xf1\x15\x13\x02\xe1\x95 \xc7\xc1\xa6\xb8\xad\x18]\x1d0\x86@\xf2\xf6Q;IT\xbbs\x0eU\x95O\xbc\'\xa4w\xb3\xf6\xdcQ\xc0\xd57H\xe4L\xfe61\x9c]\x13\x0f\r\x8b\x80\x05~N\xba+/\xa7Y*\xf2\xa4\xad\x14Xl)\xef\xac\x96\xc9\x04o\x9a\x950\xac\xb09\x08\x1b\r.\xed9\x92\xbd\x15\x92l8\xa9\xd6\xb0\x99Z>\xe2\x8b\xe7R\xb6\xc1IC\x12\x1f\x1f7Z\xdf\x1e\x04\xeb-@\xa2\x1e\xb4E\x83\xe8\xfe\xba\xbb3la\xa6\x8e\xf7\x8e\xd7\xa7Q\x81\x9f|(\xe7\xf6\xc0\x96\xdf\x01\x945\xb0\xdd=\x99\xde\xa4\xf1}(4\xe8\xf1L\xb5\x88\xb2\x9a\xde\x12\xcfn\'\xce\xb8g\x89\x0eY\x9c\x8a6-i\xafO\x0f\xbfY\x8b\xb3T\x0f"g3\xdf%r\xbakOV\xcd\xc5\x1f&\xa7\x1e$\x8c`IV\xc3\x1af\xbar\xfb2\xe1\xfe{k,\xb0\xe8{\x17\x9b\xd8\xccrM\x17&4\xd1\xad*fM\x9b\xfetW\xafU\x1bDYCW\xb25O`/p\xb7\xf4\xcb\xedI\xf9\x17~\xa7\x13\x18\xb9Vv\xb4\xa3\xe4\xde\xe8\x16\x8a\x8d%\xf3Cc\x977\x17\x947\xd7%\xac-0\xbeX@\xf2o\xad\xf1w\xa3N\xf9}\x13\xeb\xc7\x97T3\x008\xa5\xc1\x1c\xc4w\x91F\xd3L\x9eY\xd1\x89\xbdc\n\'\x80\x80\x8f\x18\xee#\xdc[\xac\xae\xe50\xdc\xa2\xec\x9c\xf1\rO\x95\xe4\x06\x8b5\xb1\xb3s\'4M\x11u\xfd\x87\xc0\x19\xa0\x0b\xc6=\xe5\xb4t\xe7\x19\x19h\xd9<w\xf4Ql\'\x99\x13\xceoD3\xa2^\xee\x94\x04V\xde\x1b\x98\xeb\x0e\xdd\x1a\x85\xf2\xc1H*\x19\x16+Z\xb2=\xb1\xbe\x0c\xb1\x90T\xc1\xbakv\xc3\xeb\x03\x85\x80\x06Np\x06 \x84\xcc\xcc\x98\xe3W\x8f$\x0e-\xd3\x1b\xb9~k\xdb\xb9\x07.\xfe\xff\x11F\xf8uN\x9a\xf7?Z\xb8\xc0\xe5\xfcP\xa7\xdc\xdb\xe9\xc4\xf1o@\xb7\xe6t\xf3\xdd\x17O\xe7a6\x97<\xc7\xedM\x97\xb7\nx\x03Z\x0f\xf2:\x15B\x07!lW\xdf\x84\xfa\n(&\xbep\xa6\x19\x1eC\x8db\x0f\x19\x85\xfbsV\xa7\x19\xf8j\xc4\x91==s\xb3\t\x00\xaf:\xc9\x86\x06zz\x80\xe7\nd\x7fwd(\xe0!\x8e %\x1d\xfcX{\x94/+\x06\x07F\xdf\x81\xe0.q\x91\xc3\x0fb\xc4\xfcI\xe7\x9a+$e(\xdbu\xd1|\x15\x10f\x14\x1f%KmR\xb0\tE\xc7\xad\xe2\xb6H\x98\x8b\xf0\x0bL{\xcbp\x16\xd5\xb5\xf1u\xc4\x801l\xd4M\x7f\x92\xe6\xbf}\x17\xe0\xc0^8U\x15~\xca\xe8&4\x10\xb6\xb2\xaf\xe0Q\xc8n\tm\x08\xbc\xc3\xfbP\xe7\xf9\xe4WNgc\x8e\x81m]x\xbbbB\xf2\xe1N\xa0br\x82`\xe4\x91\x8c\x1f"\xe4\xf2\x875\xa8(L\xedw\x1f\x05\xff\x94a\xa1T\x07\xee\xf7\xd7\xbd\xf3\x95\xd8\xf9\xb8\xd1au\xf6\x8c\xed\xd3\x8bo\xd0qa&m?\x922\xfbD\x0b)\xc5\xd6#&+\xf4\r\xf0q\x04*\xba\x0f\xd2i)\x88\xf7\xa5\x9ct5\xe7a]\x04\xd8\xac\xa1\xfcI\xb1x\xee\xfc\xc1\xe6B|9\xb6gO\xf4\xac\x9el%"\xeaq\xc4\xa3\xde\x95e\xfb\xba\xdd\x89,\xdaO\xea\xa9\x9a\x03<Dhg\xbc\x91\x07\x0eX\x00\xd9R'),
            bytearray(b'\x16>*\xef\x9e"UK\xadb-\xe7\xca)\xda\xaf \xf3\n\xd9\xc9\xccN\x06\xe4\x1aQb\xd6\xccw\x0e\x1d\xfc\x05\x12x\xe1\xc9hxpa\x13\xbf<o\x8f\x9a#\xc9\xd8\x1d\x99\x07\xae\xcf\xd980Xy\x90\x17%w\xdc3\xf0\x18\x13\x10\xed\xc6p\xce\x0f)\xbf\xe3\xaf\x04c\xc0PO\x1d\x14\x9c\xf7\x9d\xfbzd\xfeF0\x10P\xf8P\x9c\xd3\xed\xf2\xdc\xab\xf4\xa7P\x7f\x00\xbby\x1e\xcc\x85\x86\x80\x8fH%\xc7a\x1e!9QH=dv\xee\xc0\xf2.\x05\x11\xf5\xba\xc6\xd5rL\x9eV\xd1\xfd\x93aQ\x0cF\x80\xea\xb1"\x1ah\x0b\xado\xf41\x90A\x04\x92\x11\xd0\xf6F\x7f\xd1r\xff\xc1\xe6\xc3\xbf\xce\xd3\x04\x86wx\xef\xb35\x12\x94NH\\\xe7\xc8\xbe,\xcd%\x91\xb7C\xbc\x16\x0e\x95\x8e\x0e\xeb\x02\xf4\x14\xe9\xd8Ic\xcf_tk\x9b\xba@[&AB\xe7}\x83\x14\x98\xde\x8a\x1e\xbf*x\xdc\x0bJ\x1e\x1b5\xca\xa3\x99\x13\x0e\xc6\x93\x1chw\xf7b\xcc:(\x95\xe88\x12p\xd3\xdd\xaf\x9a\x8d\xba\xb6\x88T\xc2lt\xf1\x8b\x03\xf4\x9d,\xcfe\x1a`\xc6\x94/?\xd15\xc9\xcc\xdb\xec\xeaQ\r[\xa1`\n\xd8\x9a\xb16\x8a\xf2\x1e\x0e\'\xaaa\xb0\xbd\xcfMl\xc6"g@\xa9\xe0\x07\xd8nr\xd1\x17\xfdw-\xcfl\xbe\x86\\\x80\xe7U\x8a\x12\xc3\xd9]\x85\xef78\xd7\xc2\xac\x8f\xc0"\x16\x9b\x0b\xf1\rLS^\xd1\x1dK\x85\xa1|\'\x15w\xa0\x1ff\xe3\xfd\xbe\x1b\xd0\t\x12\xf6\xb9j\x07\xeaV\xbb\xc1\xdc\xaf\x8a\xc7\x08-\xee\xc3\'g\xf9}@TM&<\x03\xbfh\xe1\x0f\x84@.\xd0\xa4n\x1a\xddQ\x8e=\x90}*\x8bK\xc1N\xe5\xbe*\xd06\x1f\x7f~\xcd\x88\x97\x91\xdeaf\xd3yp\xdd\xe0\xf5\xb0\x06\x1d\xbe\x08\xb8\xd0\xa1?\x1c \x12z\x93\xfb\x8c\xac\x8c1\xbd\xb1\x83o)\xe1\xb6\x9b\xaapShn\xb0Z\x9e\xb5tW\xa0\x8c\xbb\x10\xc94\x1e\xa4\xd9\xe9D\xff\xf9\x85\xbcB\xbc\xe2\xf9t\x86\xb5\xce\x1c\x1c\xc6\x98\xb3f\x8b\x16-F\xae\x82S\xd5HN\xfb\xaa$\xa9\x00\xe8\xb6\xefuiw\xc0(\xcd\x1dW\xaco\xc0\x053\xe2\xa4u\x9aP:\xb0x\xd7\x97\x93\x10\xce\xc0\xdf\x94l\x84\x89g\x85wGgjR\x8d\xaa\x89\xf7\xd7\xe9\xf6\xbe\x84\x8dwm\n\x8ft\x956($\xc7\x87\xa6\xe2\xaf|\xdd\x81H\x02Bz\xe9\x9a\xb8\x02\x00y\x8bXn+\xf5\x0f\xa5\xd2\xa8\xb7\xe3P\xcf\rpn\xef\xf1N"n\xee\xccV\x92\xf5\xbe\x8f\xc6\xd8\xe3x\xb9\xb1\x04\x0e\x9a\xa4Ga3\xb5\xdd\xf4\xb4@\xf7\xda*\x07\x86\x16\xb7\x18ki\xec\xd9>\xca\xc31\x15r$;\xf1\xaf\xa4\xd2u7\xdc\xc0\x9e\xb8\x8f\xd1My\x92r\xf5\xd1\\#\xfb_\x9b(\xab\xe3\x95\x9cEdk\xc1\xac\xe7\xfb+\xbdZ\xc5d\x85\xc0(V\xf6$\xd8w4[\xd8z\xae\tl\xf2\xa7\x07\x07o\t\xd0\x93\x95\xa6B\x99\r\xf4\xfcm\x1e\tgw\xf8\x90\xdd~\x12\x9c\xff\xe09T\xe5\ti\x15\xa9N\xf3\x19\xa2\xbf\xb4v\xc5~\xa9\xdct\xb6\xce\xf1\xdd6\xf4\x86\xffu\x0cR@\xbb\xa6\x17\xbcN\xb0\xd6)\xeba\x7f+\xdc\x9f\x0cU\x7f2\xa9\x07\xd0qo\xea\xc1I\x8b\x90\xbd\x13\x04\xa7\x13]"\xf7\x15\xae\xcf\xf0\xe3G\xdd\\O\x0cJ{\xf1G\xffK\xd9\xfdbc)\xa98\xa2\x88\x13MT\xaf\xda\xed\xc4\xa7\x19A\x9b\xe4L\x06\xfb\x05{\xa8\xa5l3\x8e;\x97\x1d\x18P\x13\x9cBn_@\xe3X\x18!\xb6\xc4\x99WQ\x9d\xd6)\x88\xb3\xcff%{\x83\xf2NK\xca\xf0\x02\x06\xb77\xdb\xd3\xbe\x7f\x98\x03\xbf<\xe3\x0b\x05\x8b7j6\x8e\x87\x86{\x83\x16\xb8\xceD\xdf3\x1d\x9d\xb7xG\xe5y\xa4\x82r\x81\xa0\xc8\xd6CP)\xbdV\xf6\x08\xd3l\xc1\x80q\xac\xd2\x92\x86p1cK[\xdd:\n`\xe2@\xfc\x13N\x80\x11\x98\xc9\xfb\xd8\xaaE\xeeeo\xca\xc5\x1a\x07\xa4}u9X\xef\xdb\xea\xb0/\x98!\xe0#N\xdc\xf8!\x8fu\x1a\xe9'),
            bytearray(b'7\x1aE,\xd6ZA`l\xee\x05>j"x\xa3};&\x98\xda\x06O\xe5\xb0Z\xc2\x947*b\x89\xb6\xe0\x17\xc0\x96\x17\x8b\xd0\xbeb\xe42;Nh\x82\x83i\xb7\xc5\x88^\x14I\x10\x8a\xa9ez\xb2\xa6\xf8\x03\xc0%\xf3+x\xb6<\x02\xeb\x90\x8fkm\x9c\xd6\x99\xa9\xc0o\x94\xc1\x1eT\xe9\x84V\x89\xccMEkH\x05\xb3\x00G\x82\xdb\xd1>B\x07\xe7/B\xa0\t[\xb3\xdeC\xba\x94\xfb\x87=*IU\x11<Aw\x97?\xce\xa1\x07\x87\xf1\xed\x8c\xbf\x06\xbef-\xccl+ \xcf8\xec\xf52/\x00\xe3\xa8\x88\xbd\x9e\xf2\xb3\xc5\x83\xe5\xf6F\xb8\xd3S\n\xc7\xe2\xee\xfc\xf0g\xc5r\xbb\'_\xc3\xd8\xc2\xf6\xf0\x89JYt\x88\xb2O\xf6\x8f\x85\x90a\x9dQ0A\x996\x81)E\xdd&\xb3\x0c\x9a\xb2\x01\xef\xbbET\xbe{\x1a\x1f\xa8\xcbC\x14\x8d3\x805\x0c!dM\x89\xf2\xfb/\x07\x9b\xc9\xfa\xa6z\xcd\x12\x87\xdbo\xb3H\xa2b\x8d[\xdaD\n\n9\xf6\x02\x83pUj\x1b\xfc=o\xa4`\xdc\xd5\xa5\xe2\xd0\x11\x93V\xff\xa9\xed\xeb\xb8\xce\xde\xf4\xa6\x8d\xd9\xc1\xea\xc5\xd1\xaf#\x07\xe0V\xcb2\xbf;C?\xda\xbd\x1b\x97\x1dJ\x93\xb8\xde\x9d\x18\xeb\x9a\x86s\x05\x8f\xc1\x17\xd7\x05<>\xa9\x03\x1a\x04\x8e@\x8dN\x81\x06\xed\x02\x8f\x9b\x89?!\xa3[H\x072W_C?\x01\xae+\x92g\xb0\xc2DE:\x82D\x97\xf6\xb9\xd7H\xcc\xf5\xfe\naZ\xa4\xf8\x16CubL\n\x83\xe4<52\xd5\xa1I\tV\xdf\xf8\x07\xd2\xf6\xfe\\\x9d\xe0\xa1y\xda\xbb\x97\x9aE\xd2\xb7\x97\xe3\xa02\xd0kW\xd5=\xc8\xbd\x8a\xb5\xf9RA\xfb\xef\xd4\x19\xf3\x14\xcb\xdc&1\x82Kzc\x0e\x91\x86\xe7?\x1c\x91\x03\t8\x8d\xd4\x9b\x06\x14q\xa9l\x16\xa99\xf3\xe0\xc7\x9f\xd8\xa2\xfb\xd4+\xd3\x92\xcb\x10\xbd\x8b\x08\xb2.\xfd\xef6`\xba\x1eu\x80\xcd\xd4\x90\x9e\xcd=\x8b\x03\xa5;\x1c\xcd\xf5\x873<B\x90\xc3\x80\xa9\x1c"M=D\x8fP\x0e*\x98\x0e\xa8!v<\x8eO\xfb\xef\x11\xaf\xc1\xe0\x19fju\x96g:\x96\xbbv\x92\x0eA\xe1\x7fA+\xd3\xf6\x19M\xba\xf5\xb3\xec\x08\x91\xca\x19\xf6\x98TyI\xf3[f\xa7q\xc8\x9ev\xbdR\xf0\x85\xa6\xf5\xbc\x9c\x18\xbdH?~1#@\x9c\xf5\x00\xf6\xaf\xe7\xae\xab\xf4\xa3\xfe\xd2\x05\xea\xae\xec\'>m\xeeZ\x9f\xffk*\xc9\r\x86&?]4@7\xc2@\x04\x8e\xba\t\xbd\xe7eDC\xad~\xf8V1~\xee;\r\xa8\x05TSWOF\xec\xd2\x08\x129\x7f\xccR\x06\xd2\xb0\x11\xb1\t\x03\x84}I\x1b\xe8\xc2!\xc34e\xa0\xab\x88T\xcf\x14\x84\xa7J4x\x01\x97n\xeal\xfcL~V\xd6+\xd0\xc9U\xaf\x8a\xdb\x9e\x8e\x84\x9a\x98\xf2\xd1\x07vw0\xf2\xb5R\x94\xbfU\x87r!\xab\xce):!a{\x96#eMD\xb2\x0em\xc38\x0e\x8a\x9b\x89\x7f\xf1>\x01&\x10\xaa\x03\xdd\x91\x90\x04]\xd0\xdfES\xed%E\xb8\xfc\xed\xfc\x1e\xaa\x88\xd3\x10\xce\x93\t\xe0\xc1\x18%\xcc\x89]\x04\xc2~8I\xd2:\x03\x83\xe2\xed\xb9\x8c\xd1\xc0*\x882\xbb\xb0\xa1uP4\xcbR\x8f\x03\xac\x05\x9c\xbcl\x17\x9b\x9a\xbc\xa5\x0c\xbby\xb1\xba\x91\xa3\x86\xb3|_\xae\x10\xdf\xafyF}\x8d\xe1j\x9adi,K\x1d\xcby\x87\xcf\xc2\xcdp\xa4\xcbk\x8d(\'b\xcd^\xb9\xb1J6\x87\xf2\xf7j\xc4\xc6\'K\x1e\x0e\x91<@\x88\xec3\xf9\xeb\xc9\n\n\x13\x96\x8a\x16\xc7\xc4\xea(~\xb8K\xfe\x1awsvru\x94r\x97\xd9<\xca=dFT\xa9\x08\xbe\xf7\x1c\xc5\xe6]\xc1(R\x86\x1e\xf12<\x9aw\x99\x16\xab\xf2R\x1fD\xea\x95=\xbd;T\xb1\xa4\xa1\x02\xb1\xe9\xdb\xa2\xfc\xd4\xdd\xa7[\xac\xfc\xc4\x8b\xe4\xd3\x18\xdf\xae\xb4\x98eo.0\xa7M\xd0\xe9\xf8\x87D\x99\xcbJ\xfb\x03\x9fFiY\x16"\xde\xb3$\xd2\xbdJ\x98G\x8b\xb1_\xc9\xd7\x81\xca\xbbKK\xf7~R\xe4@\x99RY6'),
            bytearray(b'0\x83\xcd\xbce\x92\xefu\x01?p\xff~\x10W\xa9\xfa\x16\x89\xd1\x9d\xbe\xf6:\xd2\x9c!B\xff$z\xb9\x97]\xdf\x02\xd5\xd2K\xd5\x0e\xc1}\x97,\x0f\xdb\xa5k\xb1\xc8 J@\xa2Y\x0e\xf1\xc1g\xbc}\x9f\x9b\t\x93\xb6\xab\xf7\xd2\xfaK\xe9(D\x8cq\xedf\x03\x0c\x07\x96\xa4D\xa2\xf8,\x8d\x87B\x96\x1fqY+\xd18\x8b\x94\x03<\x1d\x80\xbc#\xcc\x8b\xef\xfdGo\xac(h,\x11\xa3\xa0\x91Y\x91!\xdf\xd2\xfe9\xf3\xa0x\xd5\xec5Qf\xd1\xdabK\xf5\xbe\x9244\xb0\xa5>\x06(@\xc6\x11Z\xe7n%,\xff\xb4\xe9\x97 \x894&\x08n~\x17\x87\xb2\x8c\x15\xcc\xa4\x8e\x86\xfb\x0f\x8c\xa4\xa6 \x9d\x92\x95Zr<\t\xdeC6\xf9\x0c\xa9mq\xcd CB\x9c\xa6g\xb7\xad \x8dY\xcb\xb5\xb7\xd4&\x9cq\x85\r\xc1\xdd\x1f\x89 \xf2\x9e\xee{\xa3h.\xba\x0e2\xb3\x84\x93\xacFY\xf5{ZG\xa4\x9a\x7fT\x81\x04\xcd_\xd9\xc75\xfbOR4\x0br\xd3\x11\xce\x90\x97-]\x87^Ug1\x14\x02\x86IS \xbd2\x128\xf1\xd0=\xa8s\x16/8:.O{\xa8\xf4ZW^\xda\x89\xa7\xa2\x11\xf8/\xa9\xd0\xf9\x19\xf67_\x9bkA\xdf\xbc\xe1v\xf6\x9e\xe6z\xe0\xd4\xb4\xef\xffuz\x14\x0c\xcd\xcb~8;Y^\xee\x06\xec\'c\xe3#\xa3\x10\xb9\xa9P\xd8\x08\xb15\xdc\xe4\xfb\xed0n\xfd~3\xd5Sh\xf3\x94\x97\x8bb]\xcb\xa3f\x0b6\xc3\x1a{\xda\xc9\xb1M\xa1\xf7\xa1\x96\xec\x11\x07\xab\x81\xd9-\xc9zz\xec\xf3W\x95^APs\x94q\t;\xb4\xea\xf4D\xeaA$\xf8+\xf9.\xbf8.^u\xfa\xbb\x17\xc7\xeb_u\x00\xa4{\xe4$\xc21XJ5\xf1\xbe"bd\x87J\x8d\xf9\x8e\x00\xa3\xb4\xdb3\x99L\x95\x1f?G\x86\xa9HL\xb8\x039+\xdfe\x0c\xeb\xa6u\xecU\xa6\x99\xb0A\x1a^\xf4Od\x9fw\x02h\xc28\xbbwp\\hi\x00\xd7\xeb\x8cKv\xe4\x9c\x1a:\xb1n\x84:\x0f\x81[\x9a\xed\xdc\xac^\xf1\xba.\xc3=3\x1c\xfaM\xdbr\xf50\xe9\xb9e\xf0-\x99+\xbe\xaa|yb\xb5\xf1S\xb8\xb5\x08\xd8\xa9\xfc\x84\xad\xbc\xd3\x15e\xb3R\x91cA\xef\xddO\xf8\xc2\xc4\xb8\xbce\xdb\xb9m\xe8\xdb\x15\xf2\xf6\x9d\x16\x1c|\xa62K\x9b\xa1\xf3\xba\x908\xfc,,\xa5\x9e\xba\x0b;C\xe7\xe9s:\xd1\x0f\xe6Y\xa9\x8b\\\xf1\xdd\x83\x03\x04\x9e$\x8a;\xa5*4\xab\xaaGV\x13R\x8f\xfa\x19\x18\xcf\xd6Ibe\x19\xa8\xcc\xf0\xbcv\x16\x93\xff\\\x13\x1d\x89\xff7\xeb\xf4\x81\xc2\xd3\x9aN8pCp\xa1\xd5%\x8c\x19\x94\xee\xa7\xc1\xf5\xf5\xff\xb5O\xfb\x04\xfd\x02A\xe8\xfaz|\xbd\x9e\xdb\xd5\xe0bO\x8eW\xfa\xe8\xc1\xac+N\x95\xc0\xa5\xcaN\x1cw\xa2bgfu\x0e\xa6\xac-2N\x9c\x08&\xc6\xdf1\xec<\x9c\xabm\xe5\xac\xa2z\xfa|\x8a#e\'{]\x92v"\xf9\x0f\xe6S\x95\x19\xbc\xacAC\xbd\xf7\xcb!(\xf9\xc2~\x1c\x95\r\xd6\x8a\xf8\xede\x1ev:\xda\xbf\x80\x1fSi\x81,sr:6\xb3K8\xd8\x86\xf6\xc2yl\xa0K$.\x0f\xca#\xc9vv9D%\x8c\xe3qJ\x94|\x01\x88\xf6\x1f1\x0e\xd3\xd0\xb1?l\x14uy\xa8\xa4OH\xcb,\x04x\xf4\xef-FU\xa9i\xc2\x8d)\xed\xe0\xa7\xdaX%\xb2\xb2\xe6^\xe3\xa6\xcd\xaahX\xef|.^\x15>\xd1\x0b\x1c\x85\x18\xb4\x1c\xdaAy\xccP\xc6\x17\x85\x19A\xaf\x11N\xbf\xb9\xbe%]\xe0@kP.\xb6i,Z\xb6\x9f\x8cH2\x8a\xd8\xa8FQPl\x14m$t\xc1\xe5u\xb3\xf9\xab\xcbsa\xd7\xf2\x82&\x16\xfa\x13Wu\xd3+\x87\xe8|n>+\xb81\x03^\xc7\t\xa4[\x90O\xebT%\x82\xd5\x05O\x9f\x87\xddF\x82t\xbf\x04\x8b}s}\xda\xc8|\xae\xb1\x9a\xad\xbc\xce\xef\xa2t\xd2\x87\x8a\xaa\r\xe9yoL\xaa,\nj\x04n\t*\x93A"8)g\xcf\n\xba\xf2Y'),
            bytearray(b'\x8f\xafe\xf6YA\xe2\r\xfdB\xf8b\x8a\xdf\xb6\xd2\xbet}=u\x13\xe3f\xdb(\xd3r\xd9K\x88d\xdcS\xfe\xf6d\xa2\x95\xee\xad0\xcd\x08\xba\xfc\xf9\x10\x11jB\x1d\xfb\xbd\xe9C\xa7\x82\x86\x16[\x81\xac\xff\x1a\xe4>\x84\xe1}\xba\xa8_Q\xb4\\\x0cJ\xdc\xda6`\xa9\x86)7\xd8\xfa\xd4\x890\\\x07\xf6s:\xf5c\xb2\xd1\xcfW`\xa6\x96=\xe8P\x18\xb8\xa3^\xa5\xb0L\xea\xb1\'i\x12%;\xbb\xc8A\xca\x9c&\xfc\x08\xab\xd5\x89\xfe\xbb\x05\xfa\x00\xebkU\xb6g\xf8qt8\x10.\xd0\xbe;\xe6\xb2L\x95M,\x9c\xb0\x06\x98\xb4\xae\xa1>\x058|;\xd3\xc3\x93\xc1\x80YH\xe3i\xd4\xd0\xd35h\xc0)4\x0fv\xc5\xd1\x96 R\xe3\xbc\x9e&(\xd9l\xf2\xdb\xfe\x12\xfa\xbb\x8a\x0es\xc2IK\xa1\xca\x94`\xe3\x14X\xfb\x84K\xb9\xc2Ch\x86#\x95\xbf\xd0\xa7\x10n\x94\xcd\x07\xc7\xdc\xd0\xc0\xcdL\xb4AL\x8d\xae\xb3\x7f\x95{X\x929\x91N\xf6\xe3\xa5\x1d;\x8d\xfd\xd8\xee\x07\x90\xd2\x13\xafG\xc9\xc3\xfe\xb3\x99\xd6(\xbax\x94\x11\xe5\xa6\xc9\x04\xa6~7XcqZ\xe8{\xad0\xc7\'\x9f\x1bZ\x95\xbf}\x1es\xa6\x1c\x1d\xff\xce\x05\xaa\x95G\t\xf7\xd0\xb1\xe4\x05 \x1b\xac\xac\x0c\xfa\xc1\'\x16/\x94\x85\xc0\x82\x88\xba$1\xcd\x88\x9cu\x88\x961\xa0\xdd\xa3\xe0v0\xdbD\xf4{\xbd\x13\x03\xb3\x7f\x03\xd7?\xc2\x00K\x07i\xff\x12\xfe\xdc\x86\x1eF\x80\\2\x84kT\x7f%\x13\x07:\xf8\xcd>(`y\x9aI\xa2\xd2\x1f\x8e\xcfy\xaa\xa7"\xd7\xef\xfap*{Yn^\xd9u\x03\x08\x85\x9e\x99\x85\xb5\xfa\xd3"\x9cOUH\t\x02\xd5\x1d\\;\xc7\xb9\xd4\x86V\xfa\xab\xb9\xbbU\x89\xf1\xf6Z\xa1*-\x10&\xcb|rqy$\xe6P8\x9e\xe2G"&\xa2\xfd\x18\xf4\xd0J&\xb6\xa0\xf0}Q\x96\xe4\xb1\xc8"\xb0x\xeb\xd98\xb4&\xf6\x05;\x92]\xa7\\\xe5j\x04D\xf6c\xbe\xd6\x8br3\xae\xb4V\xfd\x9d\x0f\xc0\xa2G\x1e\x0c{\xe7!O,\xcc\x8d-U\xd5:F\xca\xe2\xccyA\xf1\x0b\xd6\xae\x8ar\x9c,\xc59\x02\x8e\x90\x8f\xddI\x9c\xe0H\x9f\xd3>\xed\x9d\x82lU\x81\xd6\xf7^7(\xd4"k\xc4\x1cO\xa8e\xa7\xce\x1d0\xa0\xf0\xb0\x02\xb3i\xbb\xe1\xe1Z\x8e$(\xf9mM\xb6$\x0e\x01+\'\x10F<dF\xa9\xde-\r\x97&\xcfx\x9e\xb5\x10R!\xc5\xe5\xcdG\xde\xaa)\xde\x9f\xdb f\xc5;\x98Wyeg\x1fkV\xff\xaa\xbd\x129\x03\xd8\xa3\x80\xe6\xb5c_\x9d\xc8\xac\xba\x94\xbe,&@\x9ak\xf5c\x1b\xfc\x8bH\x83\xf9\xfb\rY\xc9\xa6\xfe5\x91\x92l\xcb`\xba\xad\xcat\xb3T\x99Y\t\x9f\xe1\x87\xdes\x81\xe0\xfbX\xeeGC\xd7\x06\xa4q\xd7=\xf6\x85H\x1d^\xd6\xa2\x010\xaf\xb3\x89\xb6zS\xca\xe2$\x86\xe6y\xba\xc4%\x87%L\xbf\xc5\xa2\xb4N\x85\x1cF\xe4\x06\xb2\xef\xccT\xe9\xc0\xa2I\x9e\x97\xb28\x82\x14\xa7\xe5q\x02\x1f\xba\xabyf\x07\x8c\t\xce\\\xcfR\xd5\xfd\xfc\xd9\xce\xa0\xfd\xd5\xab\xa2\x99XZ\xa7?O\xdfIl\x8b\xfdU\x8a\xbf]\xe8\x03y<\xc5\xd5\x0b\x04r\xaeO\xa9\x06}\x82f\xf0&\x93\xab\xb3\xe3@\xc60o\x1e(\xe0\x0e\xff\xfc.\x87\x0f?\xdcT#\x96\x11\xf2\xe7\xb0\xd6o\x83\xe02\x91\xa56}\xbf\x8a\xfd\xb4\x01\x84\x04;%\x94f\x9bu\xadR\x17\xe19\x0c\x1e#U\x8b\xd9c\xde\xbc\xb4\xba\x11\xfa#\xf5\x1d\xcb\x16\x0f\xad\xf7#\x8cDUz\x88\xf7\x1e\'W\xd7\xd0Qu*\x8a^\xe9Z\x97J\x1b}A\x9c\x10D\x92\x03\xa7\xf4g\x1d\xad\xa4\x8aG\x837\x81\x07\xa3J}\xc5\xfe8I\xf7\xe0g\xe1@\x9a\x1c\xa7]\xa8l{\xc8\t\x97\xb2\xa9\xb7\xa8\xe1D\x14\x89\x85\xb3\xd8j\x1e`\xa8:\xd1\x98\x85m\x85\xab%{\x8c\xb7\x1d\xa0[\xc6\xe1\xbc5\xf6\xae\x12\xb9L.\xd5\xd2\xa2S\xadhz\x05!g[\xd8F\xec\x96f\xb2\xfa#'),
            bytearray(b'\x99\x96\xec[F\xb8$\x0c\xb7\xfe\xe08\x97\x8b\x91x\xbf\xbf&a[fr\x01\xc7L\xeb\x08\x95\xf6\x19\xe9\xf8\xd2\xc6\x16`\xd5\x08cy[\xe9\xc9\x8bA\x03\xd1\xef\x83>^\x90\xab\xb3:\x84\xfa"\xed\xc1A?D<\x17c\xba\xba`\xfd\xaa\xae\x9d\xc7:j\xb3#\xa0\xa6"R(P\\\xdc\xc9s\x00&2\x10\xe7*jvJ\xa0\rU\x80R\xe1\x8e\xe9\x97\xe6\x1a\x05W\xc1{\xe3y\xbf.\xbb\xde\x11j\xf4\xdfCc\xaa\x15@2\xe6V+w:\xebD&\x9a\x8cAC\xfa7\xd6<!|\xd5\xae\xe6\xca\xe7\xbbc\x15yB7\xb7\x15\x9b\xca\xc1Rw\x9e\x13\xfa\xa4\x1f\x8a\x15VB\xe4<=\x92H"\xbcv\x18]\x83\xd7\xa6\t\xa0L\xf7}\x13\t:y\xdfZ\xc4\x19\x07\t\xa3\xc6\xeb\xa5`\x94\xbf\xb3\xe1\x95\xe0xh\xa4(um\n\x0cB\x19-\x83zU\xcd\xd8{\xb4\xab\x08Sl\xed\x0eU\xeb\xe1\xd4|\xc7\\*""\xbaB\x88\x83\xe0\xe8V\xf4{z&\xd7\xf4\x81>\xb2\xd1\x8f\xf4\xb4d\xe4\xbb~5\xbaU\xa5\x8f\xa09\xea\xc1C\xb5\x9fR\x05E%\xe0\x0bp\x1b\x88\xbb\xf1lI\xd5\xe0{\xa4\x0e\x12)o\x8a\xefr\x11\xe2\xde\xca\x14\xb0\x8c\xf1\x97\x1b\xb2o\xe8g\xc5M\xcd\xb3I\xa7C\xd7\xd7\x0b\xa5c%\xf9s\xf2I\xba\x82\x8et(W\xf8\xf1\x8a\xd6\xcc\xbc\x13\x08O\x8a\xe6\xfa`?\xae\xc2H\x1aAN)\xe8\xb5\xc3\n\xd6l~\x8d\xd73\x18r&\x98\xfb7\x84\xbc\xff\xd8\xdd\xac%u,\xfb\xbf\x04\xcc\x9d\xa4a\x17\x90\x83\xd3\xe3UV\xcd\x9f\n"6_8R\xaf`NH\xf2\xf93,_E\xa99\x99\xbbL"\x9b\xd1qv91\x844\xea\x9f\xe7\x8a&\xd0v\x0c\x8c\xd8\xfd\xb8\x97\xff\x98O\xc8\xc9:\xdf\x89\xc2\x82\xac\xcaw\xa4\xf8h\xa8i\xa5A\x07s\xbb\xed\xcdLV{\x8b\xf9\x81\xcb2\xad\xb7>\x9a\x97\xcb\xe8|x\xa3p\x93\'\xff\xce\x91\x85\xb8\xdaq\xac\xcd\x90n\x1b\xffr\xd2\xdd\xf2<\xc1\xe5\x94\xc6\xbe0\xe61\xbe\xa4\xe4\xb2\x93\xa9\xaaoI\x11\x04\xc8\'3\xe0FJ\x9f^N\xed\x8f\xb4\xcb\x128\xa3x\xeb\xc8\xdaI\xeaBBb\x1d\xc2\xe3\xdc\x7f%\xc6J\xa3\x1fF\x12\xa3s\xc8C\xe2\xde\xc5\xe0\xe7\xeb\\\xf8\x99\xf7\xd6\xa4vPg\x8f,\xe0\xcf\xef8d\x9cZ\x80\xc1\xac\xba\x14s\x8d\x05\x8a.\xd5D\xe3\xcd\x1e\xf7\xd99\xb8\xb4\x81\xf5\xa1\x1a\x11m6\x80\'y\xef\xc3r~E3h\n7Q\x14V#\xde\x81\xcc\xe0V\xd7\xb3\x84\xd5\x9c\x83\x91\xaf\xf2\x832\x10\xf1\\\x05\x14L\xdf`\xf3\xf5\x0e\xd98N6%[.2\xc3\xd4L<\xc9(\x96\x88\x84\xca\xfb\xf7e\xe4\xdd\x9e\x91DK!\x8a\\\x85\xc1U\x91\xc8APvy\xf6z\x1b\xfc\xa1\x02^;\xb8\xa5\xe0\xab\xb8\xee.\xac\t\xb9\x16T\xb7g\x11/\x0c\x81\x93\xdeR\x07\xaf\x85\xd1\xbc\xb5\xe0\xc9\xcdL\x9c\x9d\xfc\xbf\xc3K+\x87\x07u\xe6\x02\xd4c\xf4\x857=\x14\xc3{\n\xc7\x08\xcd\xee2\xa9\x9f|\x04tu\x1d\n\xd4\xdbx>A\xc0D\xf8\xadOF@\xad\xa1\xb1i\x12:1\xd9\x05N}\x13\xd6C8\xc0\x83z\xb5J\xee9\xcf\xa3\xc5\xd2\xcb\xd2\x1f\x96\x8b7\x0fw\x9b"\xab\xb9\xa2z\x81\xa8M_\xe3\xa2z\xb8\xc2\x10Q\x05,\x1c\x81\x03,\xc7di\xba\x85\x07z8!F\x989\xcd\x17$\'\xc0^\t\xd6\xe8g\xabg&\xdc\x8f\xa1V\xd1\xb0\xbc\xcf\xe5\x82_\xdf\xe5\x8d\xa8\xe4\x91\x9a\x8eC\x92\xe0/\x93E\x7f\x00\xfb\x88\xaf\x87q\xb9\x7f\xf0\x17M\xb4R\x86\x19<\xd3\x9e;\xca\xa0|\xec\x1f\xbf\x92\xb9\x83[\x19eZ\xc1\x1f\x05\x01\xc2\xbe\xca!\xc3\xaa\x92\xcfE+,\x03\x1c\x1fAA\x04v\xc9\xbc\xe6!\xf9\xfe\x82Y\xef\xb55\x99v\x82\x16\x15\xd1\x9d\xf6t\xee\xd5\xc1\xa5<Z\xd5\xd4\xd1\xdf9\xa4%\xcd\xcd\xd6\xbc\xf7\x1e\x1e"\xb6\xeef\xf0*yk\x7f\xc9>\x8f.\xa9\x01cl\x87\x95<&bW\xbf\x92\x88\x1e0s[')]
        }

def _ff_key_share(name):
    if name in _ff_precomputed:
        return random.choice(_ff_precomputed[name])
    ff_map = {'ffdhe8192' : goodGroupParameters[6],
              'ffdhe6144' : goodGroupParameters[5],
              'ffdhe4096' : goodGroupParameters[4],
              'ffdhe3072' : goodGroupParameters[3],
              'ffdhe2048' : goodGroupParameters[2]}

    generator = ff_map[name]

    secret = random.randint(2, generator[1])

    ret = numberToByteArray(powMod(generator[0], secret, generator[1]))
    return ret

class Xmas_tree(HelloConfig):
    """
    Create a Xmas tree (all options enabled) Client Hello message

    Creates a ClientHello message with maximum number of options enabled,
    currently for TLS 1.3 protocol.
    """

    def __init__(self):
        super(Xmas_tree, self).__init__()
        self._name = "Xmas tree"
        self.version = (3, 4)
        self.record_version = (3, 4)
        self.ciphers = []
        self.ciphers.extend(CipherSuite.ecdheEcdsaSuites)
        self.ciphers.extend(CipherSuite.ecdheCertSuites)
        self.ciphers.extend(CipherSuite.dheCertSuites)
        self.ciphers.extend(range(0x0100, 0x0200))
        self.ciphers.extend(CipherSuite.dheDssSuites)
        self.ciphers.extend(CipherSuite.certSuites)

        ext = self.extensions = []
        ext.append(SNIExtension())
        ext.append(TLSExtension(extType=ExtensionType.renegotiation_info)
                   .create(bytearray(1)))
        groups =[GroupName.secp256r1,
                 GroupName.secp384r1,
                 GroupName.secp521r1,
                 GroupName.ecdh_x25519,
                 GroupName.ecdh_x448]
        groups.extend(GroupName.allFF)
        ext.append(SupportedGroupsExtension().create(groups))
        formats = [ECPointFormat.uncompressed,
                   ECPointFormat.ansiX962_compressed_prime,
                   ECPointFormat.ansiX962_compressed_char2]
        ext.append(ECPointFormatsExtension().create(formats))
        ext.append(TLSExtension(extType=ExtensionType.session_ticket))
        ext.append(TLSExtension(extType=ExtensionType.max_fragment_legth)
                   .create(bytearray(b'\x04')))
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
        ext.append(TLSExtension(extType=ExtensionType.status_request_v2)
                   .create(bytearray(b'\x00\x07' +  # overall length
                                     b'\x02' +  # status type
                                     b'\x00\x04' +  # request field length
                                     b'\x00\x00' +  # responder id list
                                     b'\x00\x00')))  # request extensions
        sig_algs = []
        # some not yet standardised algorithms:
        for s_alg in [4, 5, 6, 7]:
            for alg in ['sha256', 'sha384', 'sha512']:
                sig_algs.append((getattr(HashAlgorithm, alg),
                                 s_alg))
        # some not yet standardised hashes:
        for s_alg in [SignatureAlgorithm.rsa, SignatureAlgorithm.ecdsa]:
            for alg in [7, 8, 9, 10, 11]:
                sig_algs.append((alg, s_alg))
        for alg in ['sha256', 'sha384', 'sha512', 'sha224', 'sha1', 'md5']:
            sig_algs.append((getattr(HashAlgorithm, alg),
                             SignatureAlgorithm.rsa))
        for alg in ['sha256', 'sha384', 'sha512', 'sha224', 'sha1']:
            sig_algs.append((getattr(HashAlgorithm, alg),
                             SignatureAlgorithm.ecdsa))
        for alg in ['sha256', 'sha384', 'sha512', 'sha224', 'sha1', 'md5']:
            sig_algs.append((getattr(HashAlgorithm, alg),
                             SignatureAlgorithm.dsa))
        ext.append(SignatureAlgorithmsExtension()
                   .create(sig_algs))
        ext.append(KeyShareExtension()
                   .create([(GroupName.secp384r1, _ec_key_share('secp384r1')),
                            (GroupName.secp256r1, _ec_key_share('secp256r1')),
                            (GroupName.secp521r1, _ec_key_share('secp521r1')),
                            (GroupName.ffdhe8192, _ff_key_share('ffdhe8192'))]))
        ext.append(TLSExtension(extType=ExtensionType.heartbeat)
                   .create(bytearray(b'\x01')))  # peer allowed to send
        ext.append(PaddingExtension().create(512))
        ext.append(TLSExtension(extType=ExtensionType.encrypt_then_mac))
        # place an empty extension to trigger intolerancies in specific servers
        ext.append(TLSExtension(extType=ExtensionType.extended_master_secret))

        # interesting ones are 0, 1
        self.compression_methods = list(range(0, 80))


class HugeCipherList(HelloConfig):
    """Client Hello with list of ciphers that doesn't fit a single record"""

    def __init__(self):
        super(HugeCipherList, self).__init__()
        self._name = "Huge Cipher List"
        self.record_version = (3, 1)
        self.version = (3, 3)
        self.ciphers = []
        self.ciphers.extend(CipherSuite.ecdheEcdsaSuites)
        self.ciphers.extend(CipherSuite.ecdheCertSuites)
        self.ciphers.extend(CipherSuite.dheCertSuites)
        self.ciphers.extend(CipherSuite.dheDssSuites)
        self.ciphers.extend(CipherSuite.certSuites)
        self.ciphers.extend(range(0x2000, 0x2000+8192))


class VeryCompatible(HelloConfig):
    """
    Cipher compatible client hello with minimal intolerancies

    Create a Client Hello that can connect to as many servers as possible
    without triggering intolerancies (with the exception of TLS extension
    intolerance)
    """
    def __init__(self):
        super(VeryCompatible, self).__init__()
        self._name = "Very Compatible"
        self.version = (3, 3)
        self.record_version = (3, 1)
        self.ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                        CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                        CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

        ext = self.extensions = []
        ext.append(SNIExtension())
        ext.append(SupportedGroupsExtension().create([GroupName.secp256r1,
                                                      GroupName.secp384r1,
                                                      GroupName.secp521r1]))
        ext.append(ECPointFormatsExtension().create([ECPointFormat.uncompressed]))
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


class IE_6(HelloConfig):
    """Create a Internet Explorer 6-like Client Hello message"""

    def __init__(self):
        super(IE_6, self).__init__()
        self._name = "IE 6"
        self.version = (3, 0)
        self.record_version = (0, 2)
        self.ciphers = []
        self.ciphers.extend([CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                             CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                             CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                             CipherSuite.SSL_CK_RC4_128_WITH_MD5,
                             CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
                             CipherSuite.SSL_CK_RC2_128_CBC_WITH_MD5,
                             CipherSuite.TLS_RSA_WITH_DES_CBC_SHA,
                             CipherSuite.SSL_CK_DES_64_CBC_WITH_MD5,
                             CipherSuite.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
                             CipherSuite.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                             CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                             CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                             CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5,
                             CipherSuite.SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
                             CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                             CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA,
                             CipherSuite.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA])
        self.ssl2=True


class IE_8_Win_XP(HelloConfig):
    """Create a Internet Explorer 8 on WinXP-like Client Hello message"""

    def __init__(self):
        super(IE_8_Win_XP, self).__init__()
        self._name = "IE 8 on Win XP"
        self.version = (3, 1)
        self.record_version = (3, 0)
        self.ciphers = []
        self.ciphers.extend([CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                             CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                             CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                             CipherSuite.TLS_RSA_WITH_DES_CBC_SHA,
                             CipherSuite.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
                             CipherSuite.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                             CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                             CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                             CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                             CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA,
                             CipherSuite.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA])


class IE_11_Win_7(HelloConfig):
    """Create an Internet Explorer 11 on Win7-like Client Hello message"""

    def __init__(self):
        super(IE_11_Win_7, self).__init__()
        self._name = "IE 11 on Win 7"
        self.version = (3, 3)
        self.record_version = (3, 1)
        self.ciphers = []
        self.ciphers.extend([CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                             CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                             CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                             CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                             CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                             CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                             CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                             CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                             CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                             CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                             CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                             CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                             CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                             CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                             CipherSuite.TLS_RSA_WITH_RC4_128_MD5])

        ext = self.extensions = []
        ext.append(SNIExtension())
        ext.append(TLSExtension(extType=ExtensionType.renegotiation_info)
                   .create(bytearray(1)))
        groups = [GroupName.secp256r1,
                  GroupName.secp384r1]
        ext.append(SupportedGroupsExtension().create(groups))
        ext.append(TLSExtension(extType=ExtensionType.status_request)
                   .create(bytearray(b'\x01' +
                                     b'\x00\x00' +
                                     b'\x00\x00')))
        sig_algs = []
        for s_alg in ['rsa', 'ecdsa']:
            for h_alg in ['sha256', 'sha384', 'sha1']:
                sig_algs.append((getattr(HashAlgorithm, h_alg),
                                 getattr(SignatureAlgorithm, s_alg)))
        sig_algs.append((HashAlgorithm.sha1, SignatureAlgorithm.dsa))
        ext.append(SignatureAlgorithmsExtension().create(sig_algs))


class IE_11_Win_8_1(HelloConfig):
    """Create an Internet Explorer 11 on Win8.1-like Client Hello message"""

    def __init__(self):
        super(IE_11_Win_8_1, self).__init__()
        self._name = "IE 11 on Win 8.1"
        self.version = (3, 3)
        self.record_version = (3, 1)
        self.ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA]

        ext = self.extensions = []
        ext.append(SNIExtension())
        ext.append(TLSExtension(extType=ExtensionType.renegotiation_info)
                   .create(bytearray(1)))
        groups = [GroupName.secp256r1,
                  GroupName.secp384r1]
        ext.append(SupportedGroupsExtension().create(groups))
        ext.append(TLSExtension(extType=ExtensionType.session_ticket))
        ext.append(TLSExtension(extType=ExtensionType.status_request)
                   .create(bytearray(b'\x01' +
                                     b'\x00\x00' +
                                     b'\x00\x00')))
        sig_algs = []
        for s_alg in ['rsa', 'ecdsa']:
            for h_alg in ['sha256', 'sha384', 'sha1']:
                sig_algs.append((getattr(HashAlgorithm, h_alg),
                                 getattr(SignatureAlgorithm, s_alg)))
        sig_algs.append((HashAlgorithm.sha1, SignatureAlgorithm.dsa))
        ext.append(SignatureAlgorithmsExtension().create(sig_algs))
        ext.append(NPNExtension())
        ext.append(TLSExtension(extType=ExtensionType.alpn)
                   .create(bytearray(b'\x00\x10' +
                                     b'\x06' + b'spdy/3' +
                                     b'\x08' + b'http/1.1')))
