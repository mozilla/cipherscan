#!/usr/bin/env bash

DOBENCHMARK=1
BENCHMARKITER=30
OPENSSLBIN="./openssl"
REQUEST="GET / HTTP/1.1
Host: $TARGET


"


verbose() {
    if [ $VERBOSE -eq 1 ];then
        echo $@
    fi
}


# Connect to a target host with the selected ciphersuite
test_cipher_on_target() {
    local sslcommand=$@
    local tmp=$(mktemp)
    $sslcommand 1>"$tmp" 2>/dev/null << EOF
$REQUEST
EOF
    # Parse the result
    result=$(grep "New, " $tmp|awk '{print $5}')
    rm "$tmp"
    if [ "$result" == '(NONE)' ]; then
        verbose "handshake failed, server returned ciphersuite '$result'"
        return 1
    else
        verbose "handshake succeeded, server returned ciphersuite '$result'"
        return 0
    fi
}


# Calculate the average handshake time for a specific ciphersuite
bench_cipher() {
    local ciphersuite="$1"
    local sslcommand="$OPENSSLBIN s_client -connect $TARGET -cipher $ciphersuite"
    local t="$(date +%s%N)"
    verbose "Benchmarking handshake on '$TARGET' with ciphersuite '$ciphersuite'"
    for i in $(seq 1 $BENCHMARKITER); do
        $sslcommand 2>/dev/null 1>/dev/null << EOF
$REQUEST
EOF
    done
    # Time interval in nanoseconds
    local t="$(($(date +%s%N) - t))"
    verbose "Benchmarking done in $t nanoseconds"
    # Microseconds
    cipherbenchms="$((t/1000/$BENCHMARKITER))"
}


# Connect to the target and retrieve the chosen cipher
get_cipher_pref() {
    local ciphersuite="$1"
    local sslcommand="$OPENSSLBIN s_client -connect $TARGET -cipher $ciphersuite"
    verbose "Connecting to '$TARGET' with ciphersuite '$ciphersuite'"
    test_cipher_on_target "$sslcommand"
    local success=$?
    # If the connection succeeded with the current cipher, benchmark and store
    if [ $success -eq 0 ]; then
        cipherspref=("${cipherspref[@]}" "$result")
        get_cipher_pref "!$result:$ciphersuite"
        return 0
    fi
}


if [ -z $1 ]; then
    echo "
usage: $0 <target:port> <-v>

$0 attempts to connect to a target site using all the ciphersuites it knowns.
jvehent - ulfr -  2013
"
    exit 1
fi
TARGET=$1
VERBOSE=0
if [ ! -z $2 ]; then
    if [ "$2" == "-v" ]; then
        VERBOSE=1
        echo "Loading $($OPENSSLBIN ciphers -v ALL 2>/dev/null|grep Kx|wc -l) ciphersuites from $(echo -n $($OPENSSLBIN version 2>/dev/null))"
        $OPENSSLBIN ciphers ALL 2>/dev/null
    fi
fi

cipherspref=();
results=()
get_cipher_pref "ALL"
ctr=1
for cipher in "${cipherspref[@]}"; do
    if [ $DOBENCHMARK -eq 1 ]; then
        bench_cipher "$cipher"
        r="$ctr $cipher $cipherbenchms"
    else
        r="$ctr $cipher"
    fi
    results=("${results[@]}" "$r")
    ctr=$((ctr+1))
done

if [ $DOBENCHMARK -eq 1 ]; then
    header="prio ciphersuite avg_handshake_microsec"
else
    header="prio ciphersuite"
fi
ctr=0
for result in "${results[@]}"; do
    if [ $ctr -eq 0 ]; then
        echo $header
        ctr=$((ctr+1))
    fi
    echo $result
done|column -t
