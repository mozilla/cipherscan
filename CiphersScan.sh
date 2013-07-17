#!/usr/bin/env bash

DOBENCHMARK=0
BENCHMARKITER=10
#OPENSSLBIN="/home/ulfr/Code/openssl/apps/openssl"
OPENSSLBIN=$(which openssl)
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
    $sslcommand 1>$tmp 2>/dev/null << EOF
$REQUEST
EOF
    # Parse the result
    result=$(grep "New, " $tmp|awk '{print $5}')
    rm $tmp
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
    # Milliseconds
    cipherbenchms="$((t/1000000/$BENCHMARKITER))"
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

echo
cipherspref=();
results=()
get_cipher_pref "ALL"
ctr=1
for cipher in "${cipherspref[@]}"; do
    if [ $DOBENCHMARK -eq 1 ]; then
        bench_cipher "$cipher"
        r=$(echo "$ctr $cipher $cipherbenchms"|awk '{printf "%-2d) %-30s avg_handshake= %-5d ms\n",$1,$2,$3}')
    else
        r=$(echo "$ctr $cipher"|awk '{printf "%-2d) %-30s\n",$1,$2}')
    fi
    results=("${results[@]}" "$r")
    ctr=$((ctr+1))
done

echo
echo "Ciphersuites sorted by server preference"
for result in "${results[@]}"; do
    echo $result
done

echo
echo R | $OPENSSLBIN s_client -connect $TARGET 2>/dev/null| grep 'Secure Renegotiation'|sort|uniq
