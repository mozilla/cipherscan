#!/usr/bin/env bash
parallel=50
[ ! -e "results" ] && mkdir results
i=1
while [ $i -lt 1000000 ]
do
    echo processings sites $i to $((i + parallel))
    for t in $(tail -$((1000000 - $i)) top-1m.csv | head -$parallel |cut -d ',' -f 2)
    do
        (tcping -u 10000000 $t 443; if [ $? -gt 0 ];then continue;fi;../cipherscan $t:443 -json > results/$t )&
    done
    sleep 7
    i=$(( i + parallel))
done
