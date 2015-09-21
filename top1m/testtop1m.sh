#!/usr/bin/env bash
parallel=10
max_bg=50
absolute_max_bg=400
max_load_avg=50

if [ $(ulimit -u) -lt $((10*absolute_max_bg)) ]; then
    echo "max user processes too low, use ulimit -u to increase"
    exit 1
fi
[ ! -e "results" ] && mkdir results
[ ! -e "certs" ] && mkdir certs
if [ -z "$CACERTS" ]; then
    for f in /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt; do
        if [ -e "$f" ]; then
            CACERTS="$f"
            break
        fi
    done
fi
if [ ! -e "$CACERTS" ]; then
  echo "file with CA certificates does not exist, please export CACERTS variable with location"
  exit 1
fi
if [ ! -e "ca_files" ]; then
    mkdir ca_files
    pushd ca_files >/dev/null
    awk '
      split_after == 1 {n++;split_after=0}
      /-----END CERTIFICATE-----/ {split_after=1}
      {print > "cert" n ".pem"}' < "$CACERTS"
    for i in *; do
        h=$(../../openssl x509 -hash -noout -in "$i" 2>/dev/null)
        for num in `seq 0 100`; do
            if [[ $h.$num -ef $i ]]; then
                # file already linked, ignore
                break
            fi
            if [[ ! -e $h.$num ]]; then
                # file doesn't exist, create a link
                ln -s "$i" "$h.$num"
                break
            fi
        done
    done
    popd >/dev/null
fi

function wait_for_jobs() {
    local no_jobs
    no_jobs=$(jobs | wc -l)

    while [ $no_jobs -gt $1 ] || awk -v maxload=$max_load_avg '{ if ($1 < maxload) exit 1 }' /proc/loadavg; do
        if awk -v maxload=$max_load_avg '{ if ($1 > maxload) exit 1 }' /proc/loadavg && [ $no_jobs -lt $absolute_max_bg ]; then
            return
        fi
        sleep 1
        no_jobs=$(jobs | wc -l)
    done
}

function scan_host() {
    # do not scan the same host multiple times
    if [ -e results/$1@$2 ]; then
        return
    fi
    tcping -u 10000000 $2 443;
    if [ $? -gt 0 ]; then
        return
    fi
    ../cipherscan --capath ca_files --saveca --curves --savecrt certs --delay 2 --sigalg -json -servername $1 $2:443 > results/$1@$2
}

function scan_host_no_sni() {
    # do not scan the same host multiple times
    if [ -e results/$1 ]; then
        return
    fi
    tcping -u 10000000 $1 443;
    if [ $? -gt 0 ]; then
        return
    fi
    ../cipherscan --capath ca_files --saveca --curves --savecrt certs --delay 2 --sigalg -json $1:443 > results/$1
}

function scan_hostname() {
    # check if the hostname isn't an IP address (since we can't put IP
    # addresses to SNI extension)
    if [[ ! -z $(awk -F. '$1>=0 && $1<=255 && $2>=0 && $2<=255 &&
        $3>=0 && $3<=255 && $4>=0 && $4<=255 && NF==4' <<<"$1") ]]; then
        scan_host_no_sni $1
        return
    fi

    local host_ips=$(host $1 | awk '/has address/ {print $4}')
    local www_ips=$(host www.$1 | awk '/has address/ {print $4}')
    if [ ! -z "$host_ips" ] && [ ! -z "$www_ips" ]; then
        # list of IPs that are in www but not in host
        local diff=$(grep -Fv "$host_ips" <<< "$www_ips")
        head -n 1 <<< "$host_ips" | while read ip; do
            scan_host $1 $ip
        done
        if [ ! -z "$diff" ]; then
            head -n 1 <<<"$diff" | while read ip; do
                scan_host www.$1 $ip
            done
        fi
    else
        if [ ! -z "$host_ips" ]; then
            head -n 1 <<<"$host_ips" | while read ip; do
                scan_host $1 $ip
            done
        fi
        if [ ! -z "$www_ips" ]; then
            head -n 1 <<<"$www_ips" | while read ip; do
                scan_host www.$1 $ip
            done
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
