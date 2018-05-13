#!/usr/bin/env bash

if [[ ${1,,} == "-h" ]] || [[ ${1,,} == "-help" ]] || \
    [[ ${1,,} == "--help" ]]; then
    echo "Usage: $0 [dir_name]"
    echo "Convert the system default trust store into an OpenSSL -CApath"
    echo "compatible dir"
    echo
    echo "dir_name - name of the directory in which the certificates will be"
    echo "           placed, \`ca_trusted' by default"
    exit 0
fi

DIR="${1:-ca_trusted}"

# sanity check the target directory
if [[ -e $DIR ]] && [[ ! -d $DIR ]]; then
    echo "$DIR must either not exist or be a directory!" >&2
    exit 1
fi

# prepare directory
if [[ ! -e $DIR ]]; then
    mkdir "$DIR"
    if [ $? -ne 0 ]; then
        echo "mkdir failed, check your privileges" >&2
        return 1
    fi
fi

pushd "$DIR" >/dev/null

# search for trust anchors
for f in "${CACERTS}" \
         /etc/pki/tls/certs/ca-bundle.crt \
         /etc/ssl/certs/ca-certificates.crt \
         "$(dirname $0)/../ca-bundle.crt" \
         "$(dirname $0)/../../ca-bundle.crt"; do
    if [ -e "$f" ]; then
        CACERTS="$f"
        break
    fi
done
if [ ! -e "$CACERTS" ]; then
    echo "No CA trust root store found" >&2
    return 1
fi

# search for openssl
for f in "$(dirname $0)/../openssl" \
         "$(dirname $0)/../../openssl" \
         "$(which openssl 2>/dev/null)"; do
    if [ -x "$f" ]; then
        OPENSSL="$f"
        break
    fi
done
if [ ! -x "$OPENSSL" ]; then
    echo "openssl not found!" >&2
    return 1
fi

# split the file with all CA certs into single certs
awk '
  split_after == 1 {n++;split_after=0}
  /-----END CERTIFICATE-----/ {split_after=1}
  {print > ".tmp.cert" n ".pem"}' < "$CACERTS"

# rename the files to their sha256 hashes
for file in .tmp.cert*.pem; do
    f_hash=($(${OPENSSL} x509 -in "${file}" -outform der 2>/dev/null | \
              ${OPENSSL} dgst -r -sha256 2>/dev/null))
    f_name="${f_hash[0]}.pem"
    mv ${file} ${f_name}
done

# create links that make the directory into -CApath compatible dir
for file in *.pem; do
    h=$(${OPENSSL} x509 -in "$file" -noout -hash 2>/dev/null)
    for ((num=0; num<=100; num++)); do
        if [[ ${h}.${num} -ef ${file} ]]; then
            # file already linked, skip
            break
        fi
        if [[ ! -e ${h}.${num} ]]; then
            ln -s "${file}" "${h}.${num}"
            break
        fi
    done
done

popd >/dev/null
