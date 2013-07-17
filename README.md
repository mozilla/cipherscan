CipherScan
==========
A very simple way to find out which SSL ciphersuites are supported by a target.

Run: ./CipherScan.sh www.google.com:443 -v
And watch.

Edit the script if you need more (disable benchmarking by setting DOBENCHMARK to 0).

The newer your version of openssl, the better results you'll get. Older versions
of OpenSSL don't support TLS1.2 ciphers, elliptic curves, etc... Build Your Own!

