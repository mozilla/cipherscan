CipherScan
==========
A very simple way to find out which SSL/TLS ciphersuites are supported by a target.

Cipherscan tests the ordering of the SSL/TLS ciphers on a given target, for all major versions of SSL and TLS. It also extracts some certificates informations. Cipherscan uses the `openssl s_client` command line to run the tests.

On Linux x86_64 run: ./cipherscan www.google.com:443
On any other *nix or *tux run: ./cipherscan -o /path/to/openssl www.google.com:443
and watch.

The newer your version of openssl, the better results you'll get. Versions
of OpenSSL below 1.0.1 don't support TLS1.2 ciphers, elliptic curves, etc... Build your own or test what your system's OpenSSL supports.

Cipherscan should work fine on Linux, Mac OS X, Solaris, Illumos, SmartOS, OpenIndiana if you specify a an openssl binary with -o.

Build OpenSSL with ChaCha20-Poly1305 support (Optional)
-------------------------------------------------------

The OpenSSL binary in this repository is built for 64bit Linux. If you wish to build a version with the same features for your own platform, [the snapshot from the OpenSSL gitweb view](http://git.openssl.org/gitweb/?p=openssl.git;a=tree;h=161b23361778c155f9c174694b1db2506a2e0b52;hb=9a8646510b) and build it like this:

```
./config no-shared
make
```

And get the binary from `app/openssl`. (`./config` will ask you to run `make depend` which will fail - for our purposes this step is not required)

Options
-------

```
-a | --allciphers   Test all known ciphers individually at the end.
-b | --benchmark    Activate benchmark mode.
-d | --delay        Pause for n seconds between connections
-D | --debug        Output ALL the information.
-h | --help         Shows this help text.
-j | --json         Output results in JSON format.
-o | --openssl      path/to/your/openssl binary you want to use.
-v | --verbose      Increase verbosity.
```

Example
-------

Testing plain SSL/TLS:
```
linux $ ./cipherscan www.google.com:443
...................
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
16    ECDHE-RSA-DES-CBC3-SHA       SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
17    DES-CBC3-SHA                 SSLv3,TLSv1,TLSv1.1,TLSv1.2
18    ECDHE-RSA-AES128-SHA256      TLSv1.2                      ECDH,P-256,256bits

Certificate: trusted, 2048 bit, sha1WithRSAEncryption signature
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
        },
        {
            "cipher": "AES256-SHA",
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
            "pfs": "None"
        },
        {
            "cipher": "EDH-RSA-DES-CBC3-SHA",
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
        },
        {
            "cipher": "DES-CBC3-SHA",
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
            "pfs": "None"
        },
        {
            "cipher": "DHE-RSA-AES128-SHA",
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
        },
        {
            "cipher": "AES128-SHA",
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
            "pfs": "None"
        },
        {
            "cipher": "RC4-SHA",
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
            "pfs": "None"
        },
        {
            "cipher": "RC4-MD5",
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
            "pfs": "None"
        }
    ]
}
```

Analyzing configurations
------------------------
The motivation behind cipherscan is to help admins configure good TLS on their
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

Contributors
------------

* Julien Vehent <julien@linuxwall.info> (original author)
* Hubert Kario <hkario@redhat.com>
* Pepi Zawodsky <git@maclemon.at>
* Michael Zeltner <m@niij.org>
* Simon Deziel <simon.deziel@gmail.com>
