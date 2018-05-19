#!/usr/bin/env bash
pushd "$(dirname ${BASH_SOURCE[0]})" > /dev/null
if [ ! -d ./tlslite ]; then
    echo -e "\n${BASH_SOURCE[0]}: tlslite-ng not found, downloading..." 1>&2
    git clone --depth=1 https://github.com/tomato42/tlslite-ng.git .tlslite-ng 1>&2
    ln -s .tlslite-ng/tlslite tlslite
fi
if [ ! -d ./ecdsa ]; then
    echo -e "\n${BASH_SOURCE[0]}: python-ecdsa not found, downloading..." 1>&2
    git clone --depth=1 https://github.com/warner/python-ecdsa.git .python-ecdsa 1>&2
    ln -s .python-ecdsa/src/ecdsa ecdsa
fi

# update the code if it is running in interactive terminal
#if [[ -t 1 ]]; then
if [[ $UPDATE ]]; then
    pushd .tlslite-ng >/dev/null
    git pull origin master --quiet
    popd >/dev/null
    pushd .python-ecdsa >/dev/null
    git pull origin master --quiet
    popd >/dev/null
fi

PYTHONPATH=. python cscan.py "$@"
ret=$?
popd > /dev/null
exit $ret
