CipherScan
==========
A very simple way to find out which SSL ciphersuites are supported by a target.

On Linux x86_64 run: ./cipherscan www.google.com:443
On any other *nix or *tux run: ./cipherscan -o /path/to/openssl www.google.com:443
and watch.

The newer your version of openssl, the better results you'll get. Versions
of OpenSSL below 1.0.1 don't support TLS1.2 ciphers, elliptic curves, etc... Build your own or test what your system's OpenSSL supports.

Cipherscan should work fine on Linux, Mac OS X, Solaris, Illumos, SmartOS, OpenIndiana if you specify a an openssl binary with -o.


Options
-------
Enable benchmarking by passing -b|--benchmark

You can the options below.

-a | --allciphers   Test all known ciphers individually at the end.
-b | --benchmark    Activate benchmark mode.
-h | --help         Shows this help text.
-j | --json         Output results in JSON format.
-o | --openssl      /path/to/the/openssl binary you want to use.
-v | --verbose      Increase verbosity.
	
```
linux $ ./cipherscan -json www.google.com:443
```

Example
-------

Testing plain SSL/TLS:
```
$ ./cipherscan www.google.com:443
...................
prio  ciphersuite                  protocols                    pfs_keysize
1     ECDHE-RSA-CHACHA20-POLY1305  SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
2     ECDHE-RSA-AES128-GCM-SHA256  SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
3     ECDHE-RSA-RC4-SHA            SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
4     ECDHE-RSA-AES128-SHA         SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
5     AES128-GCM-SHA256            SSLv3,TLSv1,TLSv1.1,TLSv1.2
6     RC4-SHA                      SSLv3,TLSv1,TLSv1.1,TLSv1.2
7     RC4-MD5                      SSLv3,TLSv1,TLSv1.1,TLSv1.2
8     ECDHE-RSA-AES256-GCM-SHA384  SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
9     ECDHE-RSA-AES256-SHA384      SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
10    ECDHE-RSA-AES256-SHA         SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
11    AES256-GCM-SHA384            SSLv3,TLSv1,TLSv1.1,TLSv1.2
12    AES256-SHA256                SSLv3,TLSv1,TLSv1.1,TLSv1.2
13    AES256-SHA                   SSLv3,TLSv1,TLSv1.1,TLSv1.2
14    ECDHE-RSA-DES-CBC3-SHA       SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
15    DES-CBC3-SHA                 SSLv3,TLSv1,TLSv1.1,TLSv1.2
16    ECDHE-RSA-AES128-SHA256      SSLv3,TLSv1,TLSv1.1,TLSv1.2  ECDH,P-256,256bits
17    AES128-SHA256                SSLv3,TLSv1,TLSv1.1,TLSv1.2
18    AES128-SHA                   SSLv3,TLSv1,TLSv1.1,TLSv1.2
```

Testing STARTTLS:
```
$ ./cipherscan -starttls xmpp jabber.ccc.de:5222
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
