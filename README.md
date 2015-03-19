CipherScan
==========

```bash
$ ./cipherscan jve.linuxwall.info
........................
Target: jve.linuxwall.info:443

prio  ciphersuite                  protocols              pfs_keysize
1     ECDHE-RSA-AES128-GCM-SHA256  TLSv1.2                ECDH,P-256,256bits
2     ECDHE-RSA-AES256-GCM-SHA384  TLSv1.2                ECDH,P-256,256bits
3     DHE-RSA-AES128-GCM-SHA256    TLSv1.2                DH,2048bits
4     DHE-RSA-AES256-GCM-SHA384    TLSv1.2                DH,2048bits
5     ECDHE-RSA-AES128-SHA256      TLSv1.2                ECDH,P-256,256bits
6     ECDHE-RSA-AES128-SHA         TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
7     ECDHE-RSA-AES256-SHA384      TLSv1.2                ECDH,P-256,256bits
8     ECDHE-RSA-AES256-SHA         TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
9     DHE-RSA-AES128-SHA256        TLSv1.2                DH,2048bits
10    DHE-RSA-AES128-SHA           TLSv1,TLSv1.1,TLSv1.2  DH,2048bits
11    DHE-RSA-AES256-SHA256        TLSv1.2                DH,2048bits
12    DHE-RSA-AES256-SHA           TLSv1,TLSv1.1,TLSv1.2  DH,2048bits
13    AES128-GCM-SHA256            TLSv1.2
14    AES256-GCM-SHA384            TLSv1.2
15    AES128-SHA256                TLSv1.2
16    AES256-SHA256                TLSv1.2
17    AES128-SHA                   TLSv1,TLSv1.1,TLSv1.2
18    AES256-SHA                   TLSv1,TLSv1.1,TLSv1.2
19    DHE-RSA-CAMELLIA256-SHA      TLSv1,TLSv1.1,TLSv1.2  DH,2048bits
20    CAMELLIA256-SHA              TLSv1,TLSv1.1,TLSv1.2
21    DHE-RSA-CAMELLIA128-SHA      TLSv1,TLSv1.1,TLSv1.2  DH,2048bits
22    CAMELLIA128-SHA              TLSv1,TLSv1.1,TLSv1.2
23    DES-CBC3-SHA                 TLSv1,TLSv1.1,TLSv1.2

Certificate: trusted, 2048 bit, sha256WithRSAEncryption signature
TLS ticket lifetime hint: 300
OCSP stapling: not supported
Server side cipher ordering
```

Cipherscan tests the ordering of the SSL/TLS ciphers on a given target, for all major versions of SSL and TLS. It also extracts some certificates informations, TLS options, OCSP stapling and more. Cipherscan is a wrapper above the `openssl s_client` command line.

Cipherscan is meant to run on all flavors of unix. It ships with its own built of OpenSSL for Linux/64 and Darwin/64. On other platform, it will use the openssl version provided by the operating system (which may have limited ciphers support), or your own version provided in the `-o` command line flag.

Examples
--------

Basic test:
```bash
$ ./cipherscan google.com
...................
Target: google.com:443

prio  ciphersuite                  protocols                    pfs_keysize
1     ECDHE-RSA-CHACHA20-POLY1305  TLSv1.2                      ECDH,P-256,256bits
2     ECDHE-RSA-AES128-GCM-SHA256  TLSv1.2                      ECDH,P-256,256bits
3     ECDHE-RSA-AES128-SHA         TLSv1.1,TLSv1.2              ECDH,P-256,256bits
4     ECDHE-RSA-RC4-SHA            SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
5     AES128-GCM-SHA256            TLSv1.2
6     AES128-SHA256                TLSv1.2
7     AES128-SHA                   TLSv1.1,TLSv1.2
8     RC4-SHA                      SSLv3,TLSv1,TLSv1.1,TLSv1.2
9     RC4-MD5                      SSLv3,TLSv1,TLSv1.1,TLSv1.2
10    ECDHE-RSA-AES256-GCM-SHA384  TLSv1.2                      ECDH,P-256,256bits
11    ECDHE-RSA-AES256-SHA384      TLSv1.2                      ECDH,P-256,256bits
12    ECDHE-RSA-AES256-SHA         SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
13    AES256-GCM-SHA384            TLSv1.2
14    AES256-SHA256                TLSv1.2
15    AES256-SHA                   SSLv3,TLSv1,TLSv1.1,TLSv1.2
16    ECDHE-RSA-AES128-SHA256      TLSv1.2                      ECDH,P-256,256bits
17    ECDHE-RSA-DES-CBC3-SHA       SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
18    DES-CBC3-SHA                 SSLv3,TLSv1,TLSv1.1,TLSv1.2

Certificate: trusted, 2048 bit, sha1WithRSAEncryption signature
TLS ticket lifetime hint: 100800
OCSP stapling: not supported
Server side cipher ordering
```

Testing STARTTLS:
```
darwin $ ./cipherscan -o ./openssl-mine -starttls xmpp jabber.ccc.de:5222
.........
.........
prio  ciphersuite           protocols    pfs_keysize
1     DHE-RSA-AES256-SHA    SSLv3,TLSv1  DH,1024bits
2     AES256-SHA            SSLv3,TLSv1
3     EDH-RSA-DES-CBC3-SHA  SSLv3,TLSv1  DH,1024bits
4     DES-CBC3-SHA          SSLv3,TLSv1
5     DHE-RSA-AES128-SHA    SSLv3,TLSv1  DH,1024bits
6     AES128-SHA            SSLv3,TLSv1
7     RC4-SHA               SSLv3,TLSv1
8     RC4-MD5               SSLv3,TLSv1

Certificate: UNTRUSTED, 2048 bit, sha1WithRSAEncryption signature
```

Exporting to JSON with the `-j` command line option:
```javascript
$ /cipherscan -j -starttls xmpp jabber.ccc.de:5222
{
    "target": "jabber.ccc.de:5222",
    "date": "Sat, 19 Apr 2014 11:40:40 -0400",
    "ciphersuite": [
        {
            "cipher": "DHE-RSA-AES256-SHA",
            "protocols": [
                "SSLv3",
                "TLSv1"
            ],
            "pubkey": [
                "2048"
            ],
            "sigalg": [
                "sha1WithRSAEncryption"
            ],
            "trusted": "False",
            "pfs": "DH,1024bits"
        }
    ]
}
```

Analyzing configurations
------------------------
The motivation behind cipherscan is to help operators configure good TLS on their
endpoints. To help this further, the script `analyze.py` compares the results of
a cipherscan with the TLS guidelines from https://wiki.mozilla.org/Security/Server_Side_TLS
and output a level and recommendations.

```bash
$ ./analyze.py -t jve.linuxwall.info
jve.linuxwall.info:443 has intermediate tls

Changes needed to match the old level:
* consider enabling SSLv3
* add cipher DES-CBC3-SHA
* use a certificate with sha1WithRSAEncryption signature
* consider enabling OCSP Stapling

Changes needed to match the intermediate level:
* consider enabling OCSP Stapling

Changes needed to match the modern level:
* remove cipher AES128-GCM-SHA256
* remove cipher AES256-GCM-SHA384
* remove cipher AES128-SHA256
* remove cipher AES128-SHA
* remove cipher AES256-SHA256
* remove cipher AES256-SHA
* disable TLSv1
* consider enabling OCSP Stapling
```

In the output above, `analyze.py` indicates that the target `jve.linuxwall.info`
matches the intermediate configuration level. If the administrator of this site
wants to reach the modern level, the items that failed under the modern tests
should be corrected.

`analyze.py` does not make any assumption on what a good level should be. Sites
operators should now what level they want to match against, based on the
compatibility level they want to support. Again, refer to
https://wiki.mozilla.org/Security/Server_Side_TLS for more information.

Note on Nagios mode:
`analyse.py` can be ran as a nagios check with `--nagios`. The exit code will
then represent the state of the configuration:
* 2 (critical) for bad tls
* 1 (warning) if it doesn't match the desired level
* 0 (ok) if it matches.
cipherscan can take more than 10 seconds to complete. To alleviate any timeout
issues, you may want to run it outside of nagios, passing data through some
temporary file.

OpenSSL
-------

Cipherscan uses a custom release of openssl for linux 64 bits and darwin 64
bits. OpenSSL is build from a custom branch maintained by Peter Mosmans that
includes a number of patches not merged upstream. It can be found here:
https://github.com/PeterMosmans/openssl

Contributors
------------

* Julien Vehent <julien@linuxwall.info> (original author)
* Hubert Kario <hkario@redhat.com>
* Pepi Zawodsky <git@maclemon.at>
* Michael Zeltner <m@niij.org>
* Simon Deziel <simon.deziel@gmail.com>
