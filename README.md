CipherScan
==========
A very simple way to find out which SSL ciphersuites are supported by a target.

Run: ./CipherScan.sh www.google.com:443 -v
And watch.

Edit the script if you need more (disable benchmarking by setting DOBENCHMARK to 0).

The newer your version of openssl, the better results you'll get. Older versions
of OpenSSL don't support TLS1.2 ciphers, elliptic curves, etc... Build Your Own!



Example
-------

```
$ ./CiphersScan.sh www.google.com:443


Ciphersuites sorted by server preference
1 ) ECDHE-RSA-AES128-GCM-SHA256
2 ) ECDHE-RSA-RC4-SHA
3 ) ECDHE-RSA-AES128-SHA
4 ) AES128-GCM-SHA256
5 ) RC4-SHA
6 ) RC4-MD5
7 ) ECDHE-RSA-AES256-GCM-SHA384
8 ) ECDHE-RSA-AES256-SHA384
9 ) ECDHE-RSA-AES256-SHA
10) AES256-GCM-SHA384
11) AES256-SHA256
12) AES256-SHA
13) ECDHE-RSA-DES-CBC3-SHA
14) DES-CBC3-SHA
15) ECDHE-RSA-AES128-SHA256
16) AES128-SHA256
17) AES128-SHA

Secure Renegotiation IS supported
```
