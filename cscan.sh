#!/bin/bash
pushd "$(dirname ${BASH_SOURCE[0]})" > /dev/null
if [ ! -d ./tlslite ]; then
    git clone --depth=1 https://github.com/tomato42/tlslite-ng.git .tlslite-ng &>/dev/null
    ln -s .tlslite-ng/tlslite tlslite
fi
if [ ! -d ./ecdsa ]; then
    git clone --depth=1 https://github.com/warner/python-ecdsa.git .python-ecdsa &>/dev/null
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
