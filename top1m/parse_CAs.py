#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Author: Hubert Kario - 2014

from __future__ import division, print_function

path = "./results/"
ca_certs_path = "./ca_files"
certs_path = "./certs"

""" only root CAs, no cached intermediate certs """
trust_path = "./ca_trusted"

import json
import sys
from collections import defaultdict
import os
from OpenSSL import crypto
from operator import itemgetter

invocations = defaultdict(int)

total = 0
hosts = 0
chains = defaultdict(int)
chain_len = defaultdict(int)
keysize = defaultdict(int)
keysize_per_chain = defaultdict(int)
root_CA = defaultdict(int)
sig_alg = defaultdict(int)
intermediate_CA = defaultdict(int)
effective_security = defaultdict(int)

subject_hashes = {}
issuer_hashes = {}

def get_cert_subject_name(cert):
    subject = cert.get_subject()
    commonName = None
    organization = None

    for elem,val in subject.get_components():
        if elem == "CN" and commonName is None:
            commonName = val
        if elem == "O" and organization is None:
            organization = val

    s_hash = "(" + ("%0.8X" % subject.hash()).lower() + ") "

    if commonName is not None:
        return s_hash + commonName
    elif organization is not None:
        return s_hash + organization
    else:
        return s_hash

def get_path_for_hash(cert_hash):
    f_name = certs_path + '/' + cert_hash + '.pem'
    if not os.path.exists(f_name):
        f_name = ca_certs_path + '/' + cert_hash + '.pem'
        if not os.path.exists(f_name):
            sys.stderr.write("File with hash {0} ({1}) is missing!\n".format(
                cert_hash, f_name))
            return None
    return f_name

""" convert RSA and DSA key sizes to estimated Level of Security """
def rsa_key_size_to_los(size):
    if size < 760:
        return 40
    elif size < 1020:
        return 64
    elif size < 2040:
        return 80
    elif size < 3068:
        return 112
    elif size < 4094:
        return 128
    elif size < 7660:
        return 152
    elif size < 15300:
        return 192
    else:
        return 256

""" convert signature algotihm to estimated Level of Security """
def sig_alg_to_los(name):
    if 'MD5' in name.upper():
        return 64
    elif 'SHA1' in name.upper():
        return 80
    elif 'SHA224' in name.upper():
        return 112
    elif 'SHA256' in name.upper():
        return 128
    elif 'SHA384' in name.upper():
        return 192
    elif 'SHA512' in name.upper():
        return 256
    else:
        raise UnknownSigAlgError

def collect_key_sizes(file_names):

    tmp_keysize = {}

    """ don't collect signature alg for the self signed root """
    with open(file_names[-1]) as cert_file:
        cert_pem = cert_file.read()

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    pubkey = cert.get_pubkey()
    if pubkey.type() == crypto.TYPE_RSA:
        keysize['RSA ' + str(pubkey.bits())] += 1
        tmp_keysize['RSA ' + str(pubkey.bits())] = 1
        security_level = rsa_key_size_to_los(pubkey.bits())
    elif pubkey.type() == crypto.TYPE_DSA:
        keysize['DSA ' + str(pubkey.bits())] += 1
        tmp_keysize['DSA ' + str(pubkey.bits())] = 1
        security_level = rsa_key_size_to_los(pubkey.bits())
    # following 408 should be crypto.TYPE_ECDSA, but even new(ish) version
    # of OpenSSL Python module don't define it
    elif pubkey.type() == 408:
        keysize['ECDSA ' + str(pubkey.bits())] += 1
        tmp_keysize['ECDSA ' + str(pubkey.bits())] = 1
        security_level = pubkey.bits()/2
    else:
        keysize[str(pubkey.type()) + ' ' + str(pubkey.bits())] += 1
        security_level = 0

    root_CA[get_cert_subject_name(cert)] += 1

    """ exclude the self signed root and server cert from stats """
    for f_name in file_names[1:-1]:
        with open(f_name) as cert_file:
            cert_pem = cert_file.read()

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        pubkey = cert.get_pubkey()
        if pubkey.type() == crypto.TYPE_RSA:
            keysize['RSA ' + str(pubkey.bits())] += 1
            tmp_keysize['RSA ' + str(pubkey.bits())] = 1
            c_key_level = rsa_key_size_to_los(pubkey.bits())
        elif pubkey.type() == crypto.TYPE_DSA:
            keysize['DSA ' + str(pubkey.bits())] += 1
            tmp_keysize['DSA ' + str(pubkey.bits())] = 1
            c_key_level = rsa_key_size_to_los(pubkey.bits())
        elif pubkey.type() == 408:
            keysize['ECDSA ' + str(pubkey.bits())] += 1
            tmp_keysize['ECDSA ' + str(pubkey.bits())] = 1
            c_key_level = pubkey.bits() / 2
        else:
            keysize[str(pubkey.type()) + ' ' + str(pubkey.bits())] += 1
            c_key_level = 0

        if security_level > c_key_level:
            security_level = c_key_level

        sig_alg[cert.get_signature_algorithm()] += 1
        c_sig_level = sig_alg_to_los(cert.get_signature_algorithm())
        if security_level > c_sig_level:
            security_level = c_sig_level

        intermediate_CA[get_cert_subject_name(cert)] += 1

    for key_s in tmp_keysize:
        keysize_per_chain[key_s] += 1

    # XXX doesn't handle the situation in which the CA uses its certificate
    # for a web server properly
    with open(file_names[0]) as cert_file:
       cert_pem = cert_file.read()

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    pubkey = cert.get_pubkey()
    if pubkey.type() == crypto.TYPE_RSA:
       c_key_level = rsa_key_size_to_los(pubkey.bits())
    elif pubkey.type() == crypto.TYPE_DSA:
       c_key_level = rsa_key_size_to_los(pubkey.bits())
    elif pubkey.type() == 408:
       c_key_level = pubkey.bits() / 2
    else:
       c_key_level = 0

    if security_level > c_key_level:
       security_level = c_key_level

    c_sig_level = sig_alg_to_los(cert.get_signature_algorithm())
    if security_level > c_sig_level:
       security_level = c_sig_level

    effective_security[security_level] += 1


with open("parsed") as res_file:
    for line in res_file:
        try:
            res = json.loads(line)
        except ValueError as e:
            print("can't process line: " + line)
            continue

        f=res

        try:
            server_chain_trusted = False
            server_chain_complete = False
            server_chains = []
            valid = False

            """ Keep certificates in memory for a given file """
            known_certs = {}

            if not "chains" in f:
                continue

            results = f["chains"]

            """ discard hosts with empty results """
            if len(results) < 1:
                continue

            """ loop over list of ciphers """
            for entry in results:

                """ skip invalid results """
                if not 'chain' in entry:
                    continue

                valid = True

                if entry['chain'] == "untrusted":
                    continue

                if entry['chain'] == "complete":
                    server_chain_complete = True
                    server_chain_trusted = True

                if entry['chain'] == "incomplete":
                    server_chain_trusted = True

                server_chains += [entry['certificates']]

            if server_chain_trusted:
                if server_chain_complete:
                    chains["complete"] += 1
                    print("complete: " + f['host'])
                else:
                    chains["incomplete"] += 1
                    print("incomplete: " + f['host'])
            else:
                chains["untrusted"] += 1
                print("untrusted: " + f['host'])

            if valid:
                hosts += 1

            for chain in server_chains:
                f_names = []
                for hash in chain:
                    path = get_path_for_hash(hash)
                    f_names += [path]

                collect_key_sizes(f_names)
                chain_len[str(len(chain))] += 1
                if len(chain) == 1:
                    sys.stderr.write("file with chain 1 long: " + line)
                total += 1
        except TypeError as e:

            sys.stderr.write("can't process: " + line)
            continue

""" Display stats """
#print("openssl invocations: " + str(invocations["openssl"]))

print("Statistics from " + str(total) + " chains provided by " + str(hosts) + " hosts")

print("\nServer provided chains    Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(chains):
    percent = round(chains[stat] / hosts * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(chains[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nTrusted chain statistics")
print("========================")


print("\nChain length              Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(chain_len):
    percent = round(chain_len[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(chain_len[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nCA key size in chains     Count")
print("-------------------------+---------")
for stat in sorted(keysize):
    sys.stdout.write(stat.ljust(25) + " " + str(keysize[stat]).ljust(10) + "\n")

print("\nChains with CA key        Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(keysize_per_chain):
    percent = round(keysize_per_chain[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(keysize_per_chain[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nSignature algorithm (ex. root) Count")
print("------------------------------+---------")
for stat in sorted(sig_alg):
    sys.stdout.write(stat.ljust(30) + " " + str(sig_alg[stat]).ljust(10) + "\n")

print("\nEff. host cert chain LoS  Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(effective_security):
    percent = round(effective_security[stat] / total * 100, 4)
    sys.stdout.write(str(stat).ljust(25) + " " + str(effective_security[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nRoot CAs                                      Count     Percent")
print("---------------------------------------------+---------+-------")
for stat, val in sorted(root_CA.items(), key=itemgetter(1), reverse=True):
    percent = round(val / total * 100, 4)
    sys.stdout.write(stat.ljust(45)[0:45] + " " + str(val).ljust(10) + str(percent).ljust(4) + "\n")

print("\nIntermediate CA                               Count     Percent")
print("---------------------------------------------+---------+-------")
for stat, val in sorted(intermediate_CA.items(), key=itemgetter(1), reverse=True):
    percent = round(val / total * 100, 4)
    sys.stdout.write(stat.ljust(45)[0:45] + " " + str(val).ljust(10) + str(percent).ljust(4) + "\n")
