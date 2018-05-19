#!/usr/bin/env bash

if [ ! -d ./ca_files ]; then
    echo "Directory with collected CA certificates missing!" >&2
    exit 1
fi

if [ ! -d ./ca_trusted ]; then
    echo "Directory with just trust anchors missing!" >&2
    exit 1
fi

if [ ! -d ./certs ]; then
    echo "Directory with certificates missing!" >&2
    exit 1
fi

if ! ls -f ./ca_files/????????.? > /dev/null; then
    echo "CA certificates directory not hashed properly (use c_rehash)" >&2
    exit 1
fi

if ! ls -f ./ca_trusted/????????.? > /dev/null; then
    echo "Directory with trust anchors not hashed properly (use c_rehash)" >&2
    exit 1
fi

if [ ! -d ./results ]; then
    echo "Directory with scan results missing!" >&2
    exit 1
fi

if [ ! -x ./parse_CAs ]; then
    echo "Compiling parse_CAs script"
    gcc -o parse_CAs parse_CAs.c -lssl -lcrypto -ljson-c --std=gnu99
    if [ $? -ne 0 ]; then
        echo "Compilation failed, aborting" >&2
        exit 1
    fi
fi

echo "Verifying certificate chains from results files"
./parse_CAs "$@" > parsed
echo "Calculating statistics for verified certificate chains"
python parse_CAs.py > trust_scan
echo "Done!"
echo "Results are in \"trust_scan\" file"
