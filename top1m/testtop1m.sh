#!/usr/bin/env bash
parallel=50
max_bg=400
[ ! -e "results" ] && mkdir results

function wait_for_jobs() {
    local no_jobs
    no_jobs=$(jobs | wc -l)

    while [ $no_jobs -gt $1 ]; do
        sleep 1
        no_jobs=$(jobs | wc -l)
    done
}

i=0
count=$(wc -l top-1m.csv | awk '{print $1}')
while [ $i -lt $count ]
do
    echo processings sites $i to $((i + parallel))
    for t in $(tail -$(($count - $i)) top-1m.csv | head -$parallel |cut -d ',' -f 2)
    do
        (tcping -u 10000000 $t 443;
         if [ $? -gt 0 ];then 
             tcping -u 10000000 www.$t 443; 
             if [ $? -gt 0 ]; then 
                 continue; 
             else 
                 ../cipherscan -json www.$t:443 > results/www.$t
                 continue;
             fi;
         fi;../cipherscan -json $t:443 > results/$t )&
    done
    i=$(( i + parallel))
    wait_for_jobs $max_bg
done
wait
