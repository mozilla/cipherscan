#!/usr/bin/env bash

DOBENCHMARK=0
BENCHMARKITER=30
OPENSSLBIN="./openssl"
TIMEOUT=10
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
    result="$(grep "New, " $tmp|awk '{print $5}') $(grep -E "^\s+Protocol\s+:" $tmp|awk '{print $3}')"
    rm "$tmp"
    if [ -z "$result" ]; then
        verbose "handshake failed, no ciphersuite was returned"
        result='ConnectionFailure'
        return 2
    elif [ "$result" == '(NONE) ' ]; then
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
    local sslcommand="timeout $TIMEOUT $OPENSSLBIN s_client -connect $TARGET -cipher $ciphersuite"
    local t="$(date +%s%N)"
    verbose "Benchmarking handshake on '$TARGET' with ciphersuite '$ciphersuite'"
    for i in $(seq 1 $BENCHMARKITER); do
        $sslcommand 2>/dev/null 1>/dev/null << EOF
$REQUEST
EOF
        if [ $? -gt 0 ]; then
            break
        fi
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
    local sslcommand="timeout $TIMEOUT $OPENSSLBIN s_client -connect $TARGET -cipher $ciphersuite"
    verbose "Connecting to '$TARGET' with ciphersuite '$ciphersuite'"
    test_cipher_on_target "$sslcommand"
    local success=$?
    cipherspref=("${cipherspref[@]}" "$result")
    # If the connection succeeded with the current cipher, benchmark and store
    if [ $success -eq 0 ]; then
        pciph=$(echo $result|awk '{print $1}')
        get_cipher_pref "!$pciph:$ciphersuite"
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
ALLCIPHERS=0
if [ ! -z $2 ]; then
    if [ "$2" == "-v" ]; then
        VERBOSE=1
        echo "Loading $($OPENSSLBIN ciphers -v ALL 2>/dev/null|grep Kx|wc -l) ciphersuites from $(echo -n $($OPENSSLBIN version 2>/dev/null))"
        $OPENSSLBIN ciphers ALL 2>/dev/null
    fi
    if [ "$2" == "-a" ]; then
        ALLCIPHERS=1
    fi
fi

cipherspref=();
results=()
get_cipher_pref "ALL"
ctr=1
for cipher in "${cipherspref[@]}"; do
    pciph=$(echo $cipher|awk '{print $1}')
    if [ $DOBENCHMARK -eq 1 ]; then
        bench_cipher "$pciph"
        r="$ctr $cipher $cipherbenchms"
    else
        r="$ctr $cipher"
    fi
    results=("${results[@]}" "$r")
    ctr=$((ctr+1))
done

if [ $DOBENCHMARK -eq 1 ]; then
    header="prio ciphersuite protocol avg_handshake_microsec"
else
    header="prio ciphersuite protocol"
fi
ctr=0
for result in "${results[@]}"; do
    if [ $ctr -eq 0 ]; then
        echo $header
        ctr=$((ctr+1))
    fi
    echo $result
done|column -t

if [ $ALLCIPHERS -gt 0 ]; then
    echo; echo "All accepted ciphersuites"
    for cipher in $($OPENSSLBIN ciphers -v ALL:COMPLEMENTOFALL 2>/dev/null |awk '{print $1}'|sort|uniq); do
        osslcommand="timeout $TIMEOUT $OPENSSLBIN s_client -connect $TARGET -cipher $cipher"
        test_cipher_on_target "$osslcommand"
        r=$?
        if [ $r -eq 0 ]; then
            echo -en '\E[40;32m'"OK"; tput sgr0
        else
            echo -en '\E[40;31m'"KO"; tput sgr0
        fi
        echo " $cipher"
    done
fi
