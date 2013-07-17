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
1 ) ECDHE-RSA-AES128-GCM-SHA256     avg_handshake= 502 ms
2 ) ECDHE-RSA-RC4-SHA               avg_handshake= 482 ms
3 ) ECDHE-RSA-AES128-SHA            avg_handshake= 462 ms
4 ) AES128-GCM-SHA256               avg_handshake= 495 ms
5 ) RC4-SHA                         avg_handshake= 495 ms
6 ) RC4-MD5                         avg_handshake= 517 ms
7 ) ECDHE-RSA-AES256-GCM-SHA384     avg_handshake= 503 ms
8 ) ECDHE-RSA-AES256-SHA384         avg_handshake= 476 ms
9 ) ECDHE-RSA-AES256-SHA            avg_handshake= 466 ms
10) AES256-GCM-SHA384               avg_handshake= 476 ms
11) AES256-SHA256                   avg_handshake= 534 ms
12) AES256-SHA                      avg_handshake= 464 ms
13) ECDHE-RSA-DES-CBC3-SHA          avg_handshake= 560 ms
14) DES-CBC3-SHA                    avg_handshake= 496 ms
15) ECDHE-RSA-AES128-SHA256         avg_handshake= 489 ms
16) AES128-SHA256                   avg_handshake= 522 ms
17) AES128-SHA                      avg_handshake= 464 ms

Secure Renegotiation IS supported
```
