#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

import sys, os, json, subprocess, logging, argparse
from collections import namedtuple

# is_fubar assumes that a configuration is not completely messed up
# and looks for reasons to think otherwise. it will return True if
# it finds one of these reason
def is_fubar(results):
    fubar = False
    fubar_ciphers = set(all_ciphers) - set(old_ciphers)
    for conn in results['ciphersuite']:
        if conn['cipher'] in fubar_ciphers:
            logging.debug(conn['cipher'] + ' is in the list of fubar ciphers')
            fubar = True
        if 'SSLv2' in conn['protocols']:
            logging.debug('SSLv2 is in the list of fubar protocols')
            fubar = True
        if conn['pubkey'] < 2048:
            logging.debug(conn['pubkey'] + ' is a fubar pubkey size')
            fubar = True
        if 'md5WithRSAEncryption' in conn['sigalg']:
            logging.debug(conn['sigalg']+ ' is a fubar cert signature')
            fubar = True
        if conn['trusted'] == 'False':
            logging.debug('The certificate is not trusted, which is quite fubar')
            fubar = True
    return fubar

# is_old assumes a configuration *is* old, and will return False if
# the parameters of an old configuration are not found. Those parameters
# are defined in https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility
def is_old(results):
    lvl = 'old'
    old = True
    has_sslv3 = False
    has_3des = False
    has_sha1 = True
    has_dhparam = True
    has_ocsp = True
    all_proto = []
    for conn in results['ciphersuite']:
        # flag unwanted ciphers
        if conn['cipher'] not in old_ciphers:
            logging.debug(conn['cipher'] + ' is not in the list of old ciphers')
            failures[lvl].append("remove cipher " + conn['cipher'])
            old = False
        # verify required 3des cipher is present
        if conn['cipher'] == 'DES-CBC3-SHA':
            has_3des = True
        # verify required ssl3 protocol is present
        if 'SSLv3' in conn['protocols']:
            has_sslv3 = True
        for proto in conn['protocols']:
            if proto not in all_proto:
                all_proto.append(proto)
        # verify required sha1 signature is used
        if 'sha1WithRSAEncryption' not in conn['sigalg']:
            logging.debug(conn['sigalg'][0] + ' is a not an old signature')
            old = False
            has_sha1 = False
        # verify required pfs parameter is used
        if conn['cipher'][0:2] == 'DHE':
            if conn['pfs'] != 'DH,1024bits':
                logging.debug(conn['pfs']+ ' is not a good DH parameters for the old configuration')
                old = False
                has_dhparam = False
        if conn['ocsp_stapling'] == 'False':
            has_ocsp = False
    extra_proto = set(all_proto) - set(['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2'])
    for proto in extra_proto:
        logging.debug("found protocol not wanted in the old configuration:" + proto)
        failures[lvl].append('disable ' + proto)
        modern = False
    missing_proto = set(['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2']) - set(all_proto)
    for proto in missing_proto:
        logging.debug("missing protocol wanted in the old configuration:" + proto)
        failures[lvl].append('enable ' + proto)
    if not has_sslv3:
        logging.debug("SSLv3 is not supported and required by the old configuration")
        old = False
    if not has_3des:
        logging.debug("DES-CBC3-SHA is not supported and required by the old configuration")
        failures[lvl].append("add cipher DES-CBC3-SHA")
        old = False
    if not has_sha1:
        failures[lvl].append("use a certificate with sha1WithRSAEncryption signature")
        old = False
    if not has_dhparam:
        failures[lvl].append("use a DH parameter of 1024 bits")
        old = False
    if not has_ocsp:
        failures[lvl].append("enable OCSP Stapling")
    return old

# is_intermediate is similar to is_old but for intermediate configuration from
# https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29
def is_intermediate(results):
    lvl = 'intermediate'
    inter = True
    has_tls1 = False
    has_aes = False
    has_dhparam = True
    has_sha256 = True
    has_ocsp = True
    all_proto = []
    for conn in results['ciphersuite']:
        if conn['cipher'] not in intermediate_ciphers:
            logging.debug(conn['cipher'] + ' is not in the list of intermediate ciphers')
            failures[lvl].append("remove cipher " + conn['cipher'])
            inter = False
        if conn['cipher'] == 'AES128-SHA':
            has_aes = True
        for proto in conn['protocols']:
            if proto not in all_proto:
                all_proto.append(proto)
        if 'TLSv1' in conn['protocols']:
            has_tls1 = True
        if 'sha256WithRSAEncryption' not in conn['sigalg']:
            logging.debug(conn['sigalg'][0] + ' is a not an intermediate signature')
            inter = False
            has_sha256 = False
        if conn['cipher'][0:2] == 'DHE':
            if conn['pfs'] != 'DH,2048bits':
                logging.debug(conn['pfs']+ ' is not a good DH parameters for the old configuration')
                inter = False
                has_dhparam = False
        if conn['ocsp_stapling'] == 'False':
            has_ocsp = False
    extra_proto = set(all_proto) - set(['TLSv1', 'TLSv1.1', 'TLSv1.2'])
    for proto in extra_proto:
        logging.debug("found protocol not wanted in the intermediate configuration:" + proto)
        failures[lvl].append('disable ' + proto)
        modern = False
    missing_proto = set(['TLSv1', 'TLSv1.1', 'TLSv1.2']) - set(all_proto)
    for proto in missing_proto:
        logging.debug("missing protocol wanted in the intermediate configuration:" + proto)
        failures[lvl].append('enable ' + proto)
    if not has_tls1:
        logging.debug("TLSv1 is not supported and required by the old configuration")
        inter = False
    if not has_aes:
        logging.debug("AES128-SHA is not supported and required by the intermediate configuration")
        failures[lvl].append("add cipher AES128-SHA")
        inter = False
    if not has_sha256:
        failures[lvl].append("use a certificate with sha256WithRSAEncryption signature")
        inter = False
    if not has_dhparam:
        failures[lvl].append("use a DH parameter of 2048 bits")
        inter = False
    if not has_ocsp:
        failures[lvl].append("enable OCSP Stapling")
    return inter

# is_modern is similar to is_old but for modern configuration from
# https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
def is_modern(results):
    lvl = 'modern'
    modern = True
    has_dhparam = True
    has_sha256 = True
    has_ocsp = True
    all_proto = []
    for conn in results['ciphersuite']:
        if conn['cipher'] not in modern_ciphers:
            logging.debug(conn['cipher'] + ' is not in the list of modern ciphers')
            failures[lvl].append("remove cipher " + conn['cipher'])
            modern = False
        for proto in conn['protocols']:
            if proto not in all_proto:
                all_proto.append(proto)
        if 'sha256WithRSAEncryption' not in conn['sigalg']:
            logging.debug(conn['sigalg'][0] + ' is a not an intermediate signature')
            inter = False
            has_sha256 = False
        if conn['cipher'][0:2] == 'DHE':
            if conn['pfs'] != 'DH,2048bits':
                logging.debug(conn['pfs']+ ' is not a good DH parameters for the old configuration')
                inter = False
                has_dhparam = False
        if conn['ocsp_stapling'] == 'False':
            has_ocsp = False
    extra_proto = set(all_proto) - set(['TLSv1.1', 'TLSv1.2'])
    for proto in extra_proto:
        logging.debug("found protocol not wanted in the modern configuration:" + proto)
        failures[lvl].append('disable ' + proto)
        modern = False
    missing_proto = set(['TLSv1.1', 'TLSv1.2']) - set(all_proto)
    for proto in missing_proto:
        logging.debug("missing protocol wanted in the modern configuration:" + proto)
        failures[lvl].append('enable ' + proto)
    if not has_sha256:
        failures[lvl].append("use a certificate with sha256WithRSAEncryption signature")
        modern = False
    if not has_dhparam:
        failures[lvl].append("use a DH parameter of 2048 bits")
        modern = False
    if not has_ocsp:
        failures[lvl].append("enable OCSP Stapling")
    return modern

def is_ordered(results, ciphersuite):
    return True

def evaluate_all(results):
    status = "obscure unknown ssl"

    if len(results['ciphersuite']) == 0:
        return "no ssl"

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
        return "fubar ssl"

    return status

def process_results(data, level=None):
    results = dict()
    # initialize the failures struct
    global failures
    failures = dict()
    failures['old'] = []
    failures['intermediate'] = []
    failures['modern'] = []
    try:
        results = json.loads(data)
    except ValueError, e:
        print("invalid json data")
    try:
        if results:
            print(results['target'] + " has " + evaluate_all(results))
    except TypeError, e:
        pass

    # print failures
    if level:
        if len(failures[level]) > 0:
            print("\nFailed to pass " + level + " level. The following items are failing:")
            for failure in failures[level]:
                print("* " + failure)
    else:
        for lvl in ['old', 'intermediate', 'modern']:
           if len(failures[lvl]) > 0:
                print("\nFailed to pass " + lvl + " level. The following items are failing:")
                for failure in failures[lvl]:
                    print("* " + failure)

def build_ciphers_lists():
    global all_ciphers, old_ciphers, intermediate_ciphers, modern_ciphers, errors
    # from https://wiki.mozilla.org/Security/Server_Side_TLS
    allC = 'ALL:COMPLEMENTOFALL:+aRSA'
    oldC = 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-S' \
           'HA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM' \
           '-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-' \
           'AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA' \
           '384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AE' \
           'S128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-' \
           'AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128:AES256:AES:DES-CBC3-SHA:HI' \
           'GH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-R' \
           'SA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA'
    intC = 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-S' \
           'HA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM' \
           '-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-' \
           'AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA' \
           '384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AE' \
           'S128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-' \
           'AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128:AES256:AES:CAMELLIA!aNULL:' \
           '!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC' \
           '3-SHA:!KRB5-DES-CBC3-SHA'
    modernC = 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-S' \
              'HA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM' \
              '-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-' \
              'AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA' \
              '384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AE' \
              'S128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-' \
              'AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'
    blackhole = open(os.devnull, 'w')
    logging.debug('Loading all ciphers: ' + allC)
    all_ciphers = subprocess.Popen(['./openssl', 'ciphers', allC],
        stderr=blackhole, stdout=subprocess.PIPE).communicate()[0].rstrip().split(':')
    logging.debug('Loading old ciphers: ' + oldC)
    old_ciphers = subprocess.Popen(['./openssl', 'ciphers', oldC],
        stderr=blackhole, stdout=subprocess.PIPE).communicate()[0].rstrip().split(':')
    logging.debug('Loading intermediate ciphers: ' + intC)
    intermediate_ciphers = subprocess.Popen(['./openssl', 'ciphers', intC],
        stderr=blackhole, stdout=subprocess.PIPE).communicate()[0].rstrip().split(':')
    logging.debug('Loading modern ciphers: ' + modernC)
    modern_ciphers = subprocess.Popen(['./openssl', 'ciphers', modernC],
        stderr=blackhole, stdout=subprocess.PIPE).communicate()[0].rstrip().split(':')
    blackhole.close()

def main():
    parser = argparse.ArgumentParser(
        description='Analyze cipherscan results and provides guidelines to improve configuration.',
        usage='\n* Analyze a single target, invokes cipherscan: $ ./analyze.py -t [target]' \
              '\n* Evaluate json results passed through stdin:  $ python analyze.py < target_results.json' \
              '\nexample: ./analyze.py mozilla.org',
        epilog='Julien Vehent [:ulfr] - 2014')
    parser.add_argument('-d', dest='debug', action='store_true',
        help='debug output')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'),
        default=sys.stdin, help='cipherscan json results')
    parser.add_argument('outfile', nargs='?', type=argparse.FileType('w'),
        default=sys.stdout, help='json formatted analysis')
    parser.add_argument('-l', dest='level',
        help='target configuration level [old, intermediate, modern]')
    parser.add_argument('-t', dest='target',
        help='analyze a <target>, invokes cipherscan')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    build_ciphers_lists()

    if args.target:
        # evaluate target specified as argument
        logging.debug('Invoking cipherscan with target: ' + args.target)
        data = subprocess.check_output(['./cipherscan', '-j', args.target])
        process_results(data, args.level)
    else:
        if os.fstat(args.infile.fileno()).st_size < 2:
            logging.error("invalid input file")
            parser.print_help()
            sys.exit(1)
        data = args.infile.readline()
        logging.debug('Evaluating results from stdin: ' + data)
        process_results(data, args.level)

if __name__ == "__main__":
    main()
