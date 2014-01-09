#!/usr/bin/env bash
[ ! -e "results" ] && mkdir results
i=1
while [ $i -lt 1000000 ]
do
    echo processings sites $i to $((i + 50))
    for t in $(tail -$((1000000 - $i)) top-1m.csv | head -50 |cut -d ',' -f 2)
    do
        tcping -u 2000000 $t 443
        if [ $? -gt 0 ]
        then
            continue
        fi
        ../cipherscan $t:443 > results/$t &
    done
    sleep 10
    i=$(( i + 50))
done
