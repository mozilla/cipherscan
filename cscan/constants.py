# Copyright 2016(c) Hubert Kario
# This work is released under the Mozilla Public License Version 2.0
"""Extend the tlslite-ng constants with values it does not support."""

import tlslite.constants

from tlslite.constants import CipherSuite

CipherSuite.ecdheEcdsaSuites = []

# RFC 5289
CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
CipherSuite.ietfNames[0xC02C] = 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)

CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
CipherSuite.ietfNames[0xC02B] = 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)

CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024
CipherSuite.ietfNames[0xC024] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)

CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023
CipherSuite.ietfNames[0xC023] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)

# RFC 4492
CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
CipherSuite.ietfNames[0xC00A] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)

CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
CipherSuite.ietfNames[0xC009] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)

# RFC 7251
CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0Ad
CipherSuite.ietfNames[0xC0AD] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_256_CCM)

CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC
CipherSuite.ietfNames[0xC0AC] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_128_CCM)

CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF
CipherSuite.ietfNames[0xC0AF] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8)

CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE
CipherSuite.ietfNames[0xC0AE] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8'
CipherSuite.ecdheEcdsaSuites.append(CipherSuite.
                                    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)

CipherSuite.ecdhAllSuites.extend(CipherSuite.ecdheEcdsaSuites)
CipherSuite.certAllSuites.extend(CipherSuite.ecdheEcdsaSuites)

# obsolete stuff
CipherSuite.TLS_RSA_WITH_DES_CBC_SHA = 0x0009
CipherSuite.ietfNames[0x0009] = 'TLS_RSA_WITH_DES_CBC_SHA'

CipherSuite.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA = 0x0064
CipherSuite.ietfNames[0x0064] = 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA'
CipherSuite.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x0062
CipherSuite.ietfNames[0x0062] = 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA'
CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003
CipherSuite.ietfNames[0x0003] = 'TLS_RSA_EXPORT_WITH_RC4_40_MD5'
CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006
CipherSuite.ietfNames[0x0006] = 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5'

# DSS
CipherSuite.dheDssSuites = []

CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013
CipherSuite.ietfNames[0x0013] = 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'
CipherSuite.dheDssSuites.append(CipherSuite.
                                TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)

CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x0012
CipherSuite.ietfNames[0x0012] = 'TLS_DHE_DSS_WITH_DES_CBC_SHA'
CipherSuite.dheDssSuites.append(CipherSuite.
                                TLS_DHE_DSS_WITH_DES_CBC_SHA)

CipherSuite.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x0063
CipherSuite.ietfNames[0x0063] = 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA'
CipherSuite.dheDssSuites.append(CipherSuite.
                                TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA)

CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032
CipherSuite.ietfNames[0x0032] = 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA'
CipherSuite.dheDssSuites.append(CipherSuite.
                                TLS_DHE_DSS_WITH_AES_128_CBC_SHA)

CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038
CipherSuite.ietfNames[0x0038] = 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA'
CipherSuite.dheDssSuites.append(CipherSuite.
                                TLS_DHE_DSS_WITH_AES_256_CBC_SHA)

CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040
CipherSuite.ietfNames[0x0040] = 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'
CipherSuite.dheDssSuites.append(CipherSuite.
                                TLS_DHE_DSS_WITH_AES_128_CBC_SHA256)

CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006a
CipherSuite.ietfNames[0x006a] = 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'
CipherSuite.dheDssSuites.append(CipherSuite.
                                TLS_DHE_DSS_WITH_AES_256_CBC_SHA256)


class ExtensionType(tlslite.constants.ExtensionType):
    """Definitions of TLS extension IDs."""

    status_request = 5
    alpn = 16
    session_ticket = 35

    heartbeat = 15  # RFC 6520
    status_request_v2 = 17  # RFC 6961
    padding = 21  # RFC 7685
    max_fragment_legth = 1  # RFC 6066

    # From: Eric Rescorla <ekr at rtfm.com>
    # Date: Mon, 7 Dec 2015 05:36:22 -0800
    # [TLS] TLS 1.3 ServerConfiguration
    early_data = 40
    pre_shared_key = 41
    key_share = 42
    cookie = 43


class GroupName(tlslite.constants.GroupName):
    """ECDH and FFDH key exchange group names."""

    allEC = list(tlslite.constants.GroupName.allEC)
    allFF = list(tlslite.constants.GroupName.allFF)

    ecdh_x25519 = 29
    allEC.append(ecdh_x25519)

    ecdh_x448 = 30
    allEC.append(ecdh_x448)

    eddsa_ed25519 = 31
    allEC.append(eddsa_ed25519)

    eddsa_ed448 = 32
    allEC.append(eddsa_ed448)

    all = allEC + allFF


class HandshakeType(tlslite.constants.HandshakeType):
    """Type of messages in Handshake protocol."""

    certificate_status = 22
    session_ticket = 4
