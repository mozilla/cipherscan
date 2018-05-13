#!/usr/bin/env bash

if [[ ${1,,} == "-h" ]] || [[ ${1,,} == "-help" ]] || \
    [[ ${1,,} == "-help" ]] || [[ ${#} -lt 1 ]]; then
    echo "Usage: ${0} certs_dir [target_dir]"
    echo "Create an OpenSSL -CApath compatible dir with intermediate certificates"
    echo "using a set of potentially untrusted intermediate CA certificates"
    echo "and trusted, root CAs"
    echo
    echo " certs_dir    - Directory containing untrusted certificates to test"
    echo "                one certificate per file, in PEM format"
    echo " target_dir   - where to create the -CApath directory,"
    echo "                \`ca_files' by default"
    echo
    echo "Script expects make_ca_trusted.sh in same directory as it is"
    if [[ ${#} -lt 1 ]]; then
        exit 1
    else
        exit 0
    fi
fi

UNTRUSTED="$1"
DIR="${2:-ca_files}"

# search for make_ca_trusted.sh
MAKE_CA_TRUSTED="$(dirname $0)/make_ca_trusted.sh"
if [ ! -x $MAKE_CA_TRUSTED ]; then
    echo "$MAKE_CA_TRUSTED not executable or missing" >&2
fi

# search for openssl
for f in "$(dirname $0)/openssl" \
         "$(dirname $0)/../openssl" \
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

# create a directory with initial trust anchors
"${MAKE_CA_TRUSTED}" "${DIR}"

pushd "${DIR}" >/dev/null

# find CA certificates in untrusted certs directory
unset CA_FILES
declare -a CA_FILES
CA_FILES=()
for file in "${UNTRUSTED}"/*; do
    if ${OPENSSL} x509 -in "$file" -noout -text 2>/dev/null | \
            grep -q 'CA:TRUE'; then
        CA_FILES+=("$file")
    fi
done
echo "CA's found: ${#CA_FILES[@]}"

files_added=0
# check which CA files are actually trusted, add them to the directory
cont="True"
while [[ $cont == "True" ]]; do
    cont="False"
    for file_id in "${!CA_FILES[@]}"; do
        file="${CA_FILES[$file_id]}"
        # making an "untrusted" file and using it to verify certificates
        # ends up taking much more time (6m vs 2m for 2500 certs)
        if ${OPENSSL} verify -CApath . -trusted_first\
                "$file" 2>/dev/null | grep -q ': OK$'; then

            unset CA_FILES[$file_id]

            c_sha256hash=($(${OPENSSL} x509 -in "$file" -outform DER 2>/dev/null | \
                ${OPENSSL} dgst -sha256 -r 2>/dev/null))
            if [ -e "${c_sha256hash}.pem" ]; then
                continue
            fi

            cp "$file" "${c_sha256hash}.pem"
            files_added=$((files_added+1))
            cont="True"

            c_hash=$(${OPENSSL} x509 -in "$file" -noout -hash 2>/dev/null)

            for ((i=0; i<=100; i++)); do
                if [[ ${c_hash}.$i -ef ${c_sha256hash}.pem ]]; then
                    # already linked, skip
                    break
                fi
                if [[ ! -e ${c_hash}.$i ]]; then
                    ln -s "${c_sha256hash}.pem" "${c_hash}.$i"
                    break
                fi
            done
        fi
    done
done
echo "CAs added: $files_added"

popd >/dev/null
