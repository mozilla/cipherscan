#!/usr/bin/env bash
parallel=10
max_bg=50
absolute_max_bg=100
max_load=50

if [ $(ulimit -u) -lt $((10*absolute_max_bg)) ]; then
    echo "max user processes too low, use ulimit -u to increase"
    exit 1
fi
[ ! -e "results" ] && mkdir results

function wait_for_jobs() {
    local no_jobs
    no_jobs=$(jobs | wc -l)

    while [ $no_jobs -gt $1 ] || awk -v maxload=$max_load '{ if ($1 < maxload) exit 1 }' /proc/loadavg; do
        if awk -v maxload=$max_load '{ if ($1 > maxload) exit 1 }' /proc/loadavg && [ $no_jobs -lt $absolute_max_bg ]; then
            return
        fi
        sleep 1
        no_jobs=$(jobs | wc -l)
    done
}

function scan_host() {
    tcping -u 10000000 $2 443;
    if [ $? -gt 0 ]; then
        return
    fi
    ../cipherscan -json -servername $1 $2:443 > results/$1@$2
}

function scan_hostname() {
    local host_ips=$(host $1 | awk '/has address/ {print $4}')
    local www_ips=$(host www.$1 | awk '/has address/ {print $4}')
    if [ ! -z "$host_ips" ] && [ ! -z "$www_ips" ]; then
        # list of IPs that are in www but not in host
        local diff=$(grep -Fv "$host_ips" <<< "$www_ips")
        while read ip; do
            scan_host $1 $ip
        done <<< "$host_ips"
        if [ ! -z "$diff" ]; then
            while read ip; do
                scan_host www.$1 $ip
            done <<< "$diff"
        fi
    else
        if [ ! -z "$host_ips" ]; then
            while read ip; do
                scan_host $1 $ip
            done <<< "$host_ips"
        fi
        if [ ! -z "$www_ips" ]; then
            while read ip; do
                scan_host www.$1 $ip
            done <<< "$www_ips"
        fi
    fi
}

i=0
count=$(wc -l top-1m.csv | awk '{print $1}')
while [ $i -lt $count ]
do
    echo processings sites $i to $((i + parallel))
    for t in $(tail -$(($count - $i)) top-1m.csv | head -$parallel |cut -d ',' -f 2|cut -d "/" -f 1)
    do
        (scan_hostname $t)&
    done
    i=$(( i + parallel))
    wait_for_jobs $max_bg
done
wait
