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

prio  ciphersuite                  avg_handshake_ms
1     ECDHE-RSA-AES128-GCM-SHA256  392
2     ECDHE-RSA-RC4-SHA            412
3     ECDHE-RSA-AES128-SHA         415
4     AES128-GCM-SHA256            428
5     RC4-SHA                      404
6     RC4-MD5                      399
7     ECDHE-RSA-AES256-GCM-SHA384  389
8     ECDHE-RSA-AES256-SHA384      388
9     ECDHE-RSA-AES256-SHA         394
10    AES256-GCM-SHA384            388
11    AES256-SHA256                389
12    AES256-SHA                   389
13    ECDHE-RSA-DES-CBC3-SHA       392
14    DES-CBC3-SHA                 391
15    ECDHE-RSA-AES128-SHA256      394
16    AES128-SHA256                391
17    AES128-SHA                   389
```
