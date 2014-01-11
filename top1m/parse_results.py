#!/usr/bin/env python

from __future__ import division

path = "./results/"

import json
import sys
from collections import defaultdict
import os

cipherstats = defaultdict(int)
pfsstats = defaultdict(int)
protocolstats = defaultdict(int)
handshakestats = defaultdict(int)
total = 0
for r,d,flist in os.walk(path):

    for f in flist:

        """ initialize variables for stats of the current site """
        temppfsstats = {}
        ciphertypes = 0
        AESGCM = False
        AES = False
        DES3 = False
        CAMELLIA = False
        RC4 = False
        DHE = False
        ECDHE = False
        RSA = False
        SSL2 = False
        SSL3 = False
        TLS1 = False
        TLS1_1 = False
        TLS1_2 = False

        """ process the file """
        f_abs = os.path.join(r,f)
        with open(f_abs) as json_file:
            """ discard files that fail to load """
            try:
                results = json.load(json_file)
            except ValueError:
                continue

            """ discard files with empty results """
            if len(results['ciphersuite']) < 1:
                continue

            total += 1

            """ loop over list of ciphers """
            for entry in results['ciphersuite']:

                """ store the ciphers supported """
                if 'AES-GCM' in entry['cipher']:
                    if not AESGCM:
                        AESGCM = True
                        ciphertypes += 1
                elif 'AES' in entry['cipher']:
                    if not AES:
                        AES = True
                        ciphertypes += 1
                elif 'DES-CBC3' in entry['cipher']:
                    if not DES3:
                        DES3 = True
                        ciphertypes += 1
                elif 'CAMELLIA' in entry['cipher']:
                    if not CAMELLIA:
                        CAMELLIA = True
                        ciphertypes += 1
                elif 'RC4' in entry['cipher']:
                    if not RC4:
                        ciphertypes += 1
                        RC4 = True
                else:
                    ciphertypes += 1
                    name = "z:" + entry['cipher']
                    cipherstats[name] += 1

                """ store key handshake methods """
                if 'ECDHE' in entry['cipher']:
                    ECDHE = True
                    temppfsstats[entry['pfs']] = 1
                elif 'DHE' in entry['cipher']:
                    DHE = True
                    temppfsstats[entry['pfs']] = 1

                """ store the versions of TLS supported """
                for protocol in entry['protocols']:
                    if protocol == 'SSLv2':
                        SSL2 = True
                    elif protocol == 'SSLv3':
                        SSL3 = True
                    elif protocol == 'TLSv1':
                        TLS1 = True
                    elif protocol == 'TLSv1.1':
                        TLS1_1 = True
                    elif protocol == 'TLSv1.2':
                        TLS1_2 = True
        json_file.close()

        """ done with this file, storing the stats """
        if DHE or ECDHE:
            pfsstats['Support PFS'] += 1
            if 'DHE-' in results['ciphersuite'][0]['cipher']:
                pfsstats['Prefer PFS'] += 1
            for s in temppfsstats:
                pfsstats[s] += 1

        """ store cipher stats """
        if AESGCM:
            cipherstats['AES-GCM'] += 1
            if ciphertypes == 1:
                cipherstats['AES-GCM Only'] += 1
        if AES:
            cipherstats['AES'] += 1
            if ciphertypes == 1:
                cipherstats['AES Only'] += 1
        if DES3:
            cipherstats['3DES'] += 1
            if ciphertypes == 1:
                cipherstats['3DES Only'] += 1
        if CAMELLIA:
            cipherstats['CAMELLIA'] += 1
            if ciphertypes == 1:
                cipherstats['CAMELLIA Only'] += 1
        if RC4:
            cipherstats['RC4'] += 1
            if ciphertypes == 1:
                cipherstats['RC4 Only'] += 1

        """ store handshake stats """
        if ECDHE:
            handshakestats['ECDHE'] += 1
        if DHE:
            handshakestats['DHE'] += 1
        if RSA:
            handshakestats['RSA'] += 1

        """ store protocol stats """
        if SSL2:
            protocolstats['SSL2'] += 1
            if not SSL3 and not TLS1 and not TLS1_1 and not TLS1_2:
                protocolstats['SSL2 Only'] += 1
        if SSL3:
            protocolstats['SSL3'] += 1
            if not SSL2 and not TLS1 and not TLS1_1 and not TLS1_2:
                protocolstats['SSL3 Only'] += 1
        if TLS1:
            protocolstats['TLS1'] += 1
            if not SSL2 and not SSL3 and not TLS1_1 and not TLS1_2:
                protocolstats['TLS1 Only'] += 1
        if TLS1_1:
            protocolstats['TLS1.1'] += 1
            if not SSL2 and not SSL3 and not TLS1 and not TLS1_2:
                protocolstats['TLS1_1 Only'] += 1
        if TLS1_2:
            protocolstats['TLS1.2'] += 1
            if not SSL2 and not SSL3 and not TLS1 and not TLS1_1:
                protocolstats['TLS1.2 Only'] += 1
        if TLS1_2 and not TLS1_1:
            protocolstats['TLS1.2 but not 1.1'] += 1

    # for testing, break early
    #if total % 1999 == 0:
    #    break

print("SSL/TLS survey of %i websites from Alexa's top 1 million" % total)
""" Display stats """
print("\nSupported Ciphers         Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(cipherstats):
    percent = round(cipherstats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(cipherstats[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nSupported Handshakes      Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(handshakestats):
    percent = round(handshakestats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(handshakestats[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nSupported PFS             Count     Percent  PFS Percent")
print("-------------------------+---------+--------+-----------")
for stat in sorted(pfsstats):
    percent = round(pfsstats[stat] / total * 100, 4)
    pfspercent = 0
    if "ECDH," in stat:
        pfspercent = round(pfsstats[stat] / handshakestats['ECDHE'] * 100, 4)
    elif "DH," in stat:
        pfspercent = round(pfsstats[stat] / handshakestats['DHE'] * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(pfsstats[stat]).ljust(10) + str(percent).ljust(9) + str(pfspercent) + "\n")

print("\nSupported Protocols       Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(protocolstats):
    percent = round(protocolstats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(protocolstats[stat]).ljust(10) + str(percent).ljust(4) + "\n")
