#!/usr/bin/env bash
parallel=50
max_bg=50
[ ! -e "results" ] && mkdir results

function wait_for_jobs() {
    local no_jobs
    no_jobs=$(jobs | wc -l)

    while [ $no_jobs -gt $1 ]; do
        sleep 1
        no_jobs=$(jobs | wc -l)
    done
}

function scan_host() {
    tcping -u 10000000 $1 443;
    if [ $? -gt 0 ];then
        tcping -u 10000000 www.$1 443;
        if [ $? -gt 0 ]; then
            return;
        else
            ../cipherscan -json www.$1:443 > results/www.$t
            return;
        fi;
    fi;
    ../cipherscan -json $t:443 > results/$t
}

i=0
count=$(wc -l top-1m.csv | awk '{print $1}')
while [ $i -lt $count ]
do
    echo processings sites $i to $((i + parallel))
    for t in $(tail -$(($count - $i)) top-1m.csv | head -$parallel |cut -d ',' -f 2)
    do
        (scan_host $t)&
    done
    i=$(( i + parallel))
    wait_for_jobs $max_bg
done
wait
