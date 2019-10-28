#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

from __future__ import print_function

import sys, os, json, subprocess, logging, argparse, platform, re
from collections import namedtuple
from datetime import datetime
from copy import deepcopy

try:
    from urllib2 import urlopen, URLError
except ModuleNotFoundError:
    from urllib.request import urlopen
    from urllib.error import URLError

def str_compat(data):
    if sys.version_info >= (3,0):
        data = str(data, 'utf-8')
    return data

# has_good_pfs compares a given PFS configuration with a target
# dh parameter a target elliptic curve, and return true if good
# if `must_match` is True, the exact values are expected, if not
# larger pfs values than the targets are acceptable
def has_good_pfs(pfs, target_dh, target_ecc, must_match=False):
    if target_ecc and 'ECDH,' in pfs:
        # split string, expected format is 'ECDH,P-256,256bits'
        ecc = pfs.split(',')[2].split('b')[0]
        if int(ecc) < target_ecc:
            return False
        if must_match and int(ecc) != target_ecc:
            return False
    elif target_dh and 'DH,' in pfs:
        dhparam = pfs.split(',')[1].split('b')[0]
        if int(dhparam) < target_dh:
            return False
        if must_match and int(dhparam) != target_dh:
            return False
    return True

# is_fubar assumes that a configuration is not completely messed up
# and looks for reasons to think otherwise. it will return True if
# it finds one of these reason
def is_fubar(results):
    logging.debug('entering fubar evaluation')
    lvl = 'fubar'

    fubar = False
    has_ssl2 = False
    has_wrong_pubkey = False
    has_wrong_ec_pubkey = False
    has_bad_sig = False
    has_untrust_cert = False
    has_wrong_pfs = False

    for conn in results['ciphersuite']:
        logging.debug('testing connection %s' % conn)
        pubkey_bits = int(conn['pubkey'][0])
        ec_kex = re.match(r"(ECDHE|EECDH|ECDH)-", conn['cipher'])

        if conn['cipher'] not in (set(old["openssl_ciphers"]) | set(inter["openssl_ciphers"]) | set(modern["openssl_ciphers"])):
            failures[lvl].append("remove cipher " + conn['cipher'])
            logging.debug(conn['cipher'] + ' is in the list of fubar ciphers')
            fubar = True
        if 'SSLv2' in conn['protocols']:
            has_ssl2 = True
            logging.debug('SSLv2 is in the list of fubar protocols')
            fubar = True
        if not ec_kex and pubkey_bits < 2048:
            has_wrong_pubkey = True
            logging.debug(conn['pubkey'][0] + ' is a fubar pubkey size')
            fubar = True
        if ec_kex and pubkey_bits < 256:
            has_wrong_ec_pubkey = True
            logging.debug(conn['pubkey'][0] + ' is a fubar EC pubkey size')
            fubar = True
        if conn['pfs'] != 'None':
            if not has_good_pfs(conn['pfs'], 1024, 160):
                logging.debug(conn['pfs']+ ' is a fubar PFS parameters')
                fubar = True
                has_wrong_pfs = True
        for sigalg in conn['sigalg']:
            if sigalg not in (set(old["certificate_signatures"]) | set(inter["certificate_signatures"]) | set(modern["certificate_signatures"])):
                logging.debug(sigalg + ' is a fubar cert signature')
                fubar = True
        if conn['trusted'] == 'False':
            has_untrust_cert = True
            logging.debug('The certificate is not trusted, which is quite fubar')
            fubar = True
    if has_ssl2:
        failures[lvl].append("disable SSLv2")
    if has_bad_sig:
        failures[lvl].append("don't use a cert with a bad signature algorithm")
    if has_wrong_pubkey:
        failures[lvl].append("don't use a public key smaller than 2048 bits")
    if has_wrong_ec_pubkey:
        failures[lvl].append("don't use an EC key smaller than 256 bits")
    if has_untrust_cert:
        failures[lvl].append("don't use an untrusted or self-signed certificate")
    if has_wrong_pfs:
        failures[lvl].append("don't use DHE smaller than 1024bits or ECC smaller than 160bits")
    return fubar

# is_old assumes a configuration *is* old, and will return False if
# the parameters of an old configuration are not found. Those parameters
# are defined in https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility
def is_old(results):
    logging.debug('entering old evaluation')
    lvl = 'old'
    isold = True
    has_3des = False
    has_sha1 = True
    has_pfs = True
    has_ocsp = True
    all_proto = []
    for conn in results['ciphersuite']:
        logging.debug('testing connection %s' % conn)
        # flag unwanted ciphers
        if conn['cipher'] not in old["openssl_ciphers"]:
            logging.debug(conn['cipher'] + ' is not in the list of old ciphers')
            failures[lvl].append("remove cipher " + conn['cipher'])
            isold = False
        # verify required 3des cipher is present
        if conn['cipher'] == 'DES-CBC3-SHA':
            has_3des = True
        for proto in conn['protocols']:
            if proto not in all_proto:
                all_proto.append(proto)
        # verify required sha1 signature is used
        if 'sha1WithRSAEncryption' not in conn['sigalg']:
            logging.debug(conn['sigalg'][0] + ' is a not an old signature')
            has_sha1 = False
        # verify required pfs parameter is used
        if conn['pfs'] != 'None':
            if not has_good_pfs(conn['pfs'], old["dh_param_size"], old["ecdh_param_size"], True):
                logging.debug(conn['pfs']+ ' is not a good PFS parameter for the old configuration')
                has_pfs = False
        if conn['ocsp_stapling'] == 'False':
            has_ocsp = False
    extra_proto = set(all_proto) - set(old["tls_versions"])
    for proto in extra_proto:
        logging.debug("found protocol not wanted in the old configuration:" + proto)
        failures[lvl].append('disable ' + proto)
        isold = False
    missing_proto = set(old["tls_versions"]) - set(all_proto)
    for proto in missing_proto:
        logging.debug("missing protocol wanted in the old configuration:" + proto)
        failures[lvl].append('enable ' + proto)
        isold = False
    if not has_3des:
        logging.debug("DES-CBC3-SHA is not supported and required by the old configuration")
        failures[lvl].append("add cipher DES-CBC3-SHA")
        isold = False
    if not has_sha1:
        failures[lvl].append("use a certificate with sha1WithRSAEncryption signature")
        isold = False
    if not has_pfs:
        failures[lvl].append("use DHE of {dhe}bits and ECC of {ecdhe}bits".format(
            dhe=old["dh_param_size"], ecdhe=old["ecdh_param_size"]))
        isold = False
    if not has_ocsp:
        failures[lvl].append("consider enabling OCSP Stapling")
    if results['serverside'] != ('True' if old['server_preferred_order'] else 'False'):
        failures[lvl].append("enforce server side ordering" if old['server_preferred_order'] else "enforce client side ordering")
        isold = False
    return isold

# is_intermediate is similar to is_old but for intermediate configuration from
# https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29
def is_intermediate(results):
    logging.debug('entering intermediate evaluation')
    lvl = 'intermediate'
    isinter = True
    has_tls1 = False
    has_pfs = True
    has_sigalg = True
    has_ocsp = True
    all_proto = []
    for conn in results['ciphersuite']:
        logging.debug('testing connection %s' % conn)
        if conn['cipher'] not in inter["openssl_ciphers"]:
            logging.debug(conn['cipher'] + ' is not in the list of intermediate ciphers')
            failures[lvl].append("remove cipher " + conn['cipher'])
            isinter = False
        for proto in conn['protocols']:
            if proto not in all_proto:
                all_proto.append(proto)
        if 'TLSv1' in conn['protocols']:
            has_tls1 = True
        if conn['sigalg'][0] not in inter["certificate_signatures"]:
            logging.debug(conn['sigalg'][0] + ' is a not an intermediate signature')
            has_sigalg = False
        if conn['pfs'] != 'None':
            if not has_good_pfs(conn['pfs'], inter["dh_param_size"], inter["ecdh_param_size"]):
                logging.debug(conn['pfs']+ ' is not a good PFS parameter for the intermediate configuration')
                has_pfs = False
        if conn['ocsp_stapling'] == 'False':
            has_ocsp = False
    extra_proto = set(all_proto) - set(inter["tls_versions"])
    for proto in extra_proto:
        logging.debug("found protocol not wanted in the intermediate configuration:" + proto)
        failures[lvl].append('disable ' + proto)
        isinter = False
    missing_proto = set(inter["tls_versions"]) - set(all_proto)
    for proto in missing_proto:
        logging.debug("missing protocol wanted in the intermediate configuration:" + proto)
        failures[lvl].append('consider enabling ' + proto)
    if not has_sigalg:
        failures[lvl].append("use a certificate signed with %s" % " or ".join(inter["certificate_signatures"]))
        isinter = False
    if not has_pfs:
        failures[lvl].append("consider using DHE of at least 2048bits and ECC 256bit and greater")
    if not has_ocsp:
        failures[lvl].append("consider enabling OCSP Stapling")
    if results['serverside'] != ('True' if inter['server_preferred_order'] else 'False'):
        failures[lvl].append("enforce server side ordering" if inter['server_preferred_order'] else "enforce client side ordering")
        isinter = False
    return isinter

# is_modern is similar to is_old but for modern configuration from
# https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
def is_modern(results):
    logging.debug('entering modern evaluation')
    lvl = 'modern'
    ismodern = True
    has_pfs = True
    has_sigalg = True
    has_ocsp = True
    all_proto = []
    for conn in results['ciphersuite']:
        logging.debug('testing connection %s' % conn)
        if conn['cipher'] not in modern["openssl_ciphers"]:
            logging.debug(conn['cipher'] + ' is not in the list of modern ciphers')
            failures[lvl].append("remove cipher " + conn['cipher'])
            ismodern = False
        for proto in conn['protocols']:
            if proto not in all_proto:
                all_proto.append(proto)
        if conn['sigalg'][0] not in modern["certificate_signatures"]:
            logging.debug(conn['sigalg'][0] + ' is a not an modern signature')
            has_sigalg = False
        if conn['pfs'] != 'None':
            if not has_good_pfs(conn['pfs'], modern["dh_param_size"], modern["ecdh_param_size"], True):
                logging.debug(conn['pfs']+ ' is not a good PFS parameter for the modern configuration')
                ismodern = False
                has_pfs = False
        if conn['ocsp_stapling'] == 'False':
            has_ocsp = False
    extra_proto = set(all_proto) - set(modern["tls_versions"])
    for proto in extra_proto:
        logging.debug("found protocol not wanted in the modern configuration:" + proto)
        failures[lvl].append('disable ' + proto)
        ismodern = False
    missing_proto = set(modern["tls_versions"]) - set(all_proto)
    for proto in missing_proto:
        logging.debug("missing protocol wanted in the modern configuration:" + proto)
        failures[lvl].append('consider enabling ' + proto)
    if not has_sigalg:
        failures[lvl].append("use a certificate signed with %s" % " or ".join(modern["certificate_signatures"]))
        ismodern = False
    if not has_pfs:
        failures[lvl].append("use DHE of at least 2048bits and ECC 256bit and greater")
        ismodern = False
    if not has_ocsp:
        failures[lvl].append("consider enabling OCSP Stapling")
    if results['serverside'] != ('True' if modern['server_preferred_order'] else 'False'):
        failures[lvl].append("enforce server side ordering" if modern['server_preferred_order'] else "enforce client side ordering")
        ismodern = False
    return ismodern

def is_ordered(results, ref_ciphersuite, lvl):
    ordered = True
    previous_pos = 0
    # iterate through the list of ciphers returned by the target
    for conn in results['ciphersuite']:
        pos = 0
        # compare against each cipher of the reference ciphersuite
        for ref_cipher in ref_ciphersuite:
            # if the target cipher matches the reference ciphersuite,
            # look for its position against the reference and flag cipher
            # that violate the reference ordering
            if conn['cipher'] == ref_cipher:
                logging.debug("{0} found in reference ciphersuite at position {1}".format(conn['cipher'], pos))
                if pos < previous_pos:
                    failures[lvl].append("increase priority of {0} over {1}".format(conn['cipher'], ref_ciphersuite[previous_pos]))
                    ordered = False
                # save current position
                previous_pos = pos
            pos += 1
    if not ordered:
        failures[lvl].append("fix ciphersuite ordering, use recommended " + lvl + " ciphersuite")
    return ordered

def evaluate_all(results):
    status = "obscure or unknown"

    if len(results['ciphersuite']) == 0:
        return "no"

    if is_old(results):
        status = "old"
        if old["server_preferred_order"] and not is_ordered(results, old["openssl_ciphers"], "old"):
            status = "old with bad ordering"

    if is_intermediate(results):
        status = "intermediate"
        if inter["server_preferred_order"] and not is_ordered(results, inter["openssl_ciphers"], "intermediate"):
            status = "intermediate with bad ordering"

    if is_modern(results):
        status = "modern"
        if modern["server_preferred_order"] and not is_ordered(results, modern["openssl_ciphers"], "modern"):
            status = "modern with bad ordering"

    if is_fubar(results):
        status = "bad"

    return status

def process_results(data, level=None, do_json=False, do_nagios=False):
    logging.debug('processing results on %s' % data)
    exit_status = 0
    results = dict()
    # initialize the failures struct
    global failures
    json_output = dict()
    failures = dict()
    failures['fubar'] = []
    failures['old'] = []
    failures['intermediate'] = []
    failures['modern'] = []
    if not level:
        level='none'
    try:
        results = json.loads(data)
    except ValueError as e:
        print("invalid json data: " + str(e))
    try:
        if results:
            if do_json:
                json_output['target'] = results['target']
                d = datetime.utcnow()
                json_output['utctimestamp'] = d.isoformat("T") + "Z"
                json_output['level'] = evaluate_all(results)
                json_output['target_level'] = level
                json_output['compliance'] = False
                if json_output['target_level'] in json_output['level']:
                    json_output['compliance'] = True
                if operator:
                    json_output['operator'] = operator
            else:
                measured_lvl = evaluate_all(results)
                print(results['target'] + " has " + measured_lvl + " ssl/tls")
                if level != 'none':
                    if level in measured_lvl:
                        print("and complies with the '" + level + "' level")
                    else:
                        print("and DOES NOT comply with the '" + level + "' level")
    except TypeError as e:
        print("Error processing data: " + str(e))
        return False

    if do_json:
        json_output['failures'] = deepcopy(failures)
        print(json.dumps(json_output))
        return True

    if len(failures['fubar']) > 0:
        print("\nThings that are bad:")
        for failure in failures['fubar']:
            print("* " + failure)
        if do_nagios:
            exit_status = 2

    # print failures
    if level != 'none':
        if len(failures[level]) > 0:
            print("\nChanges needed to match the " + level + " level:")
            for failure in failures[level]:
                print("* " + failure)
            if do_nagios and exit_status < 2:
                exit_status = 1
    else:
        for lvl in ['old', 'intermediate', 'modern']:
           if len(failures[lvl]) > 0:
                print("\nChanges needed to match the " + lvl + " level:")
                for failure in failures[lvl]:
                    print("* " + failure)
                if do_nagios and exit_status < 2:
                    exit_status = 1
    return exit_status

def build_ciphers_lists():
    sstlsurl = "https://statics.tls.security.mozilla.org/server-side-tls-conf.json"
    conf = dict()
    try:
        raw = urlopen(sstlsurl).read()
        conf = json.loads(raw)
        logging.debug('retrieving online server side tls recommendations from %s' % sstlsurl)
    except URLError:
        with open('server-side-tls-conf.json', 'r') as f:
            conf = json.load(f)
            logging.debug('Error connecting to %s; using local archive of server side tls recommendations' % sstlsurl)
    except:
        print("failed to retrieve JSON configurations from %s" % sstlsurl)
        sys.exit(23)

    global old, inter, modern
    old = conf["configurations"]["old"]
    inter = conf["configurations"]["intermediate"]
    modern = conf["configurations"]["modern"]

def main():
    parser = argparse.ArgumentParser(
        description='Analyze cipherscan results and provides guidelines to improve configuration.',
        usage='\n* Analyze a single target, invokes cipherscan: $ ./analyze.py -t [target]' \
              '\n* Evaluate json results passed through stdin:  $ python analyze.py target_results.json' \
              '\nexample: ./analyze.py -t mozilla.org',
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
    parser.add_argument('-o', dest='openssl',
        help='path to openssl binary, if you don\'t like the default')
    parser.add_argument('-j', dest='json', action='store_true',
        help='output results in json format')
    parser.add_argument('--ops', dest='operator',
        help='optional name of the operator\'s team added into the JSON output (for database insertion)')
    parser.add_argument('--nagios', dest='nagios', action='store_true',
        help='use nagios-conformant exit codes')
    args = parser.parse_args()

    global mypath
    mypath = os.path.dirname(os.path.realpath(sys.argv[0]))

    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    global operator
    operator=''
    if args.operator:
        operator=args.operator

    build_ciphers_lists()

    if args.target:
        # evaluate target specified as argument
        logging.debug('Invoking cipherscan with target: ' + args.target)
        data=''
        if args.openssl:
            data = subprocess.check_output([mypath + '/cipherscan', '-o', args.openssl, '-j', args.target])
        else:
            data = subprocess.check_output([mypath + '/cipherscan', '-j', args.target])
        data = str_compat(data)
        exit_status=process_results(str(data), args.level, args.json, args.nagios)
    else:
        if os.fstat(args.infile.fileno()).st_size < 2:
            logging.error("invalid input file")
            parser.print_help()
            if args.nagios:
                sys.exit(3)
            else:
                sys.exit(1)
        data = args.infile.readline()
        logging.debug('Evaluating results from stdin: ' + data)
        exit_status=process_results(data, args.level, args.json, args.nagios)
    sys.exit(exit_status)

if __name__ == "__main__":
    main()
