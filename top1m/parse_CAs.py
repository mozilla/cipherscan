#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Author: Hubert Kario - 2014

from __future__ import division

path = "./results/"
ca_certs_path = "./ca_files"
certs_path = "./certs"

""" only root CAs, no cached intermediate certs """
trust_path = "./ca_trusted"

import json
import sys
from collections import defaultdict
import os
import re
import subprocess
from OpenSSL import crypto
from M2Crypto import X509, EVP
from m2ext import _m2ext
from m2ext import SSL
import glob

from pprint import pprint

# override m2ext implementation so that it is possible to provide additional
# certificates to be used during verification. Requires m2ext with a small fix
# from https://github.com/tomato42/m2ext/tree/extended_ctx_init
class Context(SSL.Context):
    def validate_certificate(self, cert, chain=None):
        """
        Validate a certificate using this SSL Context
        """
        if chain:
            ptr = chain._ptr()
        else:
            ptr = None
        store_ctx = X509.X509_Store_Context(_m2ext.x509_store_ctx_new(), _pyfree=1)
        _m2ext.x509_store_ctx_init(store_ctx.ctx,
                                   self.get_cert_store().store,
                                   cert.x509, ptr)
        rc = _m2ext.x509_verify_cert(store_ctx.ctx)
        if rc < 0:
            raise SSL.SSLError("Empty context")
        return rc != 0


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

def get_cert_hashes(path):
    if path in subject_hashes:
        return subject_hashes[path], issuer_hashes[path]

    with open(path) as srv_c_f:
        srv_c_pem = srv_c_f.read()

    srv_c = crypto.load_certificate(crypto.FILETYPE_PEM, srv_c_pem)

    # can't make M2Crypto to output OpenSSL-compatible hashes...
    subject_hash = ("%0.8X" % srv_c.get_subject().hash()).lower()
    issuer_hash = ("%0.8X" % srv_c.get_issuer().hash()).lower()

    subject_hashes[path] = subject_hash
    issuer_hashes[path] = issuer_hash

    return subject_hash, issuer_hash

def gen_cert_paths(paths):

    # failsafe in case of a loop in path resolution
    if len(paths) > 10:
        return

    subject_hash, issuer_hash = get_cert_hashes(paths[-1])

    if subject_hash == issuer_hash:
        yield paths
    else:
        for ca_file in glob.glob(ca_certs_path + '/' + issuer_hash + ".*"):
            for perm in gen_cert_paths(paths + [ca_file]):
                if not perm in paths:
                    yield perm

def is_chain_complete_f(file_names):

    stack = X509.X509_Stack()
    for f_name in file_names[1:]:
        cert = X509.load_cert(f_name)
        stack.push(cert)

    cert = X509.load_cert(file_names[0])

    return trusted_context.validate_certificate(cert, stack)

def is_chain_complete(certs):

    stack = X509.X509_Stack()

    for cert in certs[1:]:
        stack.push(cert)

    return trusted_context.validate_certificate(certs[0], stack)

def is_chain_trusted(cert_hashes):

    c_hash = cert_hashes[0]
    """ first check the likely option: the cert dir """
    file_name = certs_path + '/' + c_hash + '.pem'
    if not os.path.exists(file_name):
        """ then try the unlikely option: ca directory """
        file_name = ca_certs_path + '/' + c_hash + '.pem'
        if not os.path.exists(file_name):
            print "File with hash " + c_hash + " is missing!"
            return False,None

    for cert_paths in gen_cert_paths([ file_name ]):
        if is_chain_complete_f(cert_paths):
            return True,cert_paths

    return False,None

def get_path_for_hash(cert_hash):
    f_name = certs_path + '/' + c_hash + '.pem'
    if not os.path.exists(f_name):
        f_name = ca_certs_path + '/' + c_hash + '.pem'
        if not os.path.exists(f_name):
            #print "File with hash " + c_hash + " is missing!"
            return None
    return f_name

def is_chain_trusted_at_all(cert_list):
    certs = []
    stack = X509.X509_Stack()

    cert = cert_list[0]

    for ca in cert_list[1:]:
        stack.push(ca)

    return all_CAs_context.validate_certificate(cert, stack)

""" convert RSA and DSA key sizes to estimated Level of security """
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

def sig_alg_to_los(name):
    if 'SHA1' in name.upper():
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


all_CAs_context = Context()
all_CAs_context.load_verify_locations(capath=ca_certs_path)
trusted_context = Context()
trusted_context.load_verify_locations(capath=trust_path)

for r,d,flist in os.walk(path):
    for f in flist:

        server_chain_trusted = False
        server_chain_complete = False
        server_chains = []
        chains_tested = []
        valid = True

        """ process the file """
        f_abs = os.path.join(r,f)
        with open(f_abs) as json_file:
            """ Keep certificates in memory for a given file """
            known_certs = {}

            """ discard files that fail to load """
            try:
                results = json.load(json_file)
            except ValueError:
                continue

            """ discard files with empty results """
            if len(results['ciphersuite']) < 1:
                continue

            valid = True

            """ loop over list of ciphers """
            for entry in results['ciphersuite']:

                """ skip entries which don't have certificate references """
                if not 'certificates' in entry:
                    continue

                """ skip entries for A(EC)DH suites """
                if len(entry['certificates']) < 1:
                    continue

                if not entry['certificates'] in chains_tested:
                    certs = []

                    for c_hash in entry['certificates']:
                        if c_hash in known_certs:
                            certs += [known_certs[c_hash]]
                        else:
                            path = get_path_for_hash(c_hash)
                            if path is None:
                                continue
                            cert = X509.load_cert(path)
                            known_certs[c_hash] = cert
                            certs += [cert]

                    if is_chain_trusted_at_all(certs):
                        ret,tmpchain = is_chain_trusted(entry['certificates'])
                        if ret:
                            server_chain_trusted = True
                            if not tmpchain in server_chains:
                                server_chains += [tmpchain]
                            if is_chain_complete(certs):
                                server_chain_complete = True

                    chains_tested += [entry['certificates']]

        if server_chain_trusted:
            if server_chain_complete:
                chains["complete"] += 1
                print "complete: " + f
            else:
                chains["incomplete"] += 1
                print "incomplete: " + f
        else:
            chains["untrusted"] += 1
            print "untrusted: " + f

        if valid:
            hosts += 1

        for chain in server_chains:
            collect_key_sizes(chain)
            chain_len[str(len(chain))] += 1
            if len(chain) == 1:
                print "file with chain 1 long " + f_abs
            total += 1

""" Display stats """
#print "openssl invocations: " + str(invocations["openssl"])

print "Statistics from " + str(total) + " chains provided by " + str(hosts) + " hosts"

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
for stat in sorted(root_CA):
    percent = round(root_CA[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(45)[0:45] + " " + str(root_CA[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nIntermediate CA                               Count     Percent")
print("---------------------------------------------+---------+-------")
for stat in sorted(intermediate_CA):
    percent = round(intermediate_CA[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(45)[0:45] + " " + str(intermediate_CA[stat]).ljust(10) + str(percent).ljust(4) + "\n")
