CipherScan
==========
A very simple way to find out which SSL ciphersuites are supported by a target.

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
3     ECDHE-RSA-AES128-SHA         TLSv1.2                      ECDH,P-256,256bits
4     ECDHE-RSA-RC4-SHA            SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
5     AES128-GCM-SHA256            TLSv1.2
6     AES128-SHA256                TLSv1.2
7     AES128-SHA                   TLSv1.2
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
```

Testing STARTTLS:
```
darwin $ ./cipherscan -o ./openssl-mine -starttls xmpp jabber.ccc.de:5222
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
```
