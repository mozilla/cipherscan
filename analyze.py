#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

import fileinput
import sys
import json
import subprocess
from collections import defaultdict

def is_fubar(results):
    fubar_ciphers = set(all_ciphers) - set(old_ciphers)
    for conn in results['ciphersuite']:
        if conn['cipher'] in fubar_ciphers:
            return True
        if 'SSLv2' in conn['protocols']:
            return True
        if conn['pubkey'] < 2048:
            return True
    return False

def is_old(results):
    for conn in results['ciphersuite']:
        if conn['cipher'] not in old_ciphers:
            return False
        if 'SSLv3' not in conn['protocols']:
            return False
        if 'sha1WithRSAEncryption' not in conn['sigalg']:
            return False
    return True

def is_intermediate(results):
    for conn in results['ciphersuite']:
        if conn['cipher'] not in intermediate_ciphers:
            return False
        if len(set(conn['protocols']) - set(['TLSv1', 'TLSv1.1', 'TLSv1.2'])) > 0:
            return False
    return True

def is_modern(results):
    for conn in results['ciphersuite']:
        if conn['cipher'] not in modern_ciphers:
            errors["modern"]["ciphers"].append(conn['cipher'])
            return False
        if len(set(conn['protocols']) - set(['TLSv1.1', 'TLSv1.2'])) > 0:
            # deprecated protocols are supported
            return False
    return True

def is_ordered(results, ciphersuite):
    return True

def evaluate(results):
    status = "obscure unknown ssl"

    if len(results['ciphersuite']) == 0:
        status = "no ssl"

    if is_modern(results):
        if is_ordered(results, modern_ciphers):
            status = "modern tls"
        else:
            status = "modern tls with bad ordering"

    if is_intermediate(results):
        if is_ordered(results, intermediate_ciphers):
            status = "intermediate tls"
        else:
            status = "intermediate tls with bad ordering"

    if is_old(results):
        if is_ordered(results, old_ciphers):
            status = "old ssl"
        else:
            status = "old ssl with bad ordering"

    if is_fubar(results):
        status = "fubar ssl"

    return status

def process_results(data):
    results = dict()
    try:
        results = json.loads(data)
    except ValueError, e:
        print("invalid json data")
    try:
        if results:
            print(results['target'] + " has " + evaluate(results))
    except TypeError, e:
        pass

def main():
    global all_ciphers, old_ciphers, intermediate_ciphers, modern_ciphers, errors
    all_ciphers = subprocess.check_output(['./openssl', 'ciphers', all_ciphersuite]).rstrip().split(':')
    old_ciphers = subprocess.check_output(['./openssl', 'ciphers', old_ciphersuite]).rstrip().split(':')
    intermediate_ciphers = subprocess.check_output(['./openssl', 'ciphers', intermediate_ciphersuite]).rstrip().split(':')
    modern_ciphers = subprocess.check_output(['./openssl', 'ciphers', modern_ciphersuite]).rstrip().split(':')
    if len(sys.argv) > 1:
        # evaluate target specified as argument
        data = subprocess.check_output(['./cipherscan', '-j', sys.argv[1]])
        process_results(data)
    else:
        # take input from stdin
        for data in fileinput.input():
            if data:
                process_results(data)
    print errors
# from https://wiki.mozilla.org/Security/Server_Side_TLS
all_ciphersuite = "ALL:COMPLEMENTOFALL:+aRSA"
old_ciphersuite = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128:AES256:AES:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"
intermediate_ciphersuite = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128:AES256:AES:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"
modern_ciphersuite = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"
errors = defaultdict(str)

if __name__ == "__main__":
    main()
