#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Author: Julien Vehent [:ulfr] - 2013
# Contributors: Hubert Kario - 2014

from __future__ import division

path = "./results/"

import json
import sys
from collections import defaultdict
import os
import re

def natural_sort(l):
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
    return sorted(l, key = alphanum_key)

""" list of ciphers offerred by Firefox 29 by default """
firefox_ciphers=[
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-ECDSA-AES128-SHA',
        'ECDHE-RSA-AES128-SHA',
        'ECDHE-RSA-AES256-SHA',
        'ECDHE-RSA-DES-CBC3-SHA',
        'ECDHE-ECDSA-RC4-SHA',
        'ECDHE-RSA-RC4-SHA',
        'DHE-RSA-AES128-SHA',
        'DHE-DSS-AES128-SHA',
        'DHE-RSA-CAMELLIA128-SHA',
        'DHE-RSA-AES256-SHA',
        'DHE-DSS-AES256-SHA',
        'DHE-RSA-CAMELLIA256-SHA',
        'EDH-RSA-DES-CBC3-SHA',
        'AES128-SHA',
        'CAMELLIA128-SHA',
        'AES256-SHA',
        'CAMELLIA256-SHA',
        'DES-CBC3-SHA',
        'RC4-SHA',
        'RC4-MD5']

report_untrused=False

cipherstats = defaultdict(int)
FF_RC4_Only_cipherstats = defaultdict(int)
FF_RC4_preferred_cipherstats = defaultdict(int)
FF_incompatible_cipherstats = defaultdict(int)
FF_selected_cipherstats = defaultdict(int)
cipherordering = defaultdict(int)
pfsstats = defaultdict(int)
protocolstats = defaultdict(int)
handshakestats = defaultdict(int)
keysize = defaultdict(int)
sigalg = defaultdict(int)
tickethint = defaultdict(int)
ocspstaple = defaultdict(int)
dsarsastack = 0
total = 0
for r,d,flist in os.walk(path):

    for f in flist:

        """ initialize variables for stats of the current site """
        temppfsstats = {}
        tempkeystats = {}
        tempecckeystats = {}
        tempdsakeystats = {}
        tempsigstats = {}
        tempticketstats = {}
        tempcipherstats = {}
        ciphertypes = 0
        AESGCM = False
        AES = False
        CHACHA20 = False
        DES3 = False
        CAMELLIA = False
        RC4 = False
        """ the following depends on FF_compat, so by default it can be True """
        RC4_Only_FF = True
        FF_compat = False
        temp_FF_incompat = {}
        list_of_ciphers = []
        FF_RC4_Pref = None
        FF_selected = None
        ADH = False
        DHE = False
        AECDH = False
        ECDHE = False
        RSA = False
        ECDH = False
        DH = False
        SSL2 = False
        SSL3 = False
        TLS1 = False
        TLS1_1 = False
        TLS1_2 = False
        dualstack = False
        ECDSA = False
        trusted = False
        ocsp_stapling = None

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

            """ loop over list of ciphers """
            for entry in results['ciphersuite']:

                # some servers return different certificates with different
                # ciphers, also we may become redirected to other server with
                # different config (because over-reactive IPS)
                if 'False' in entry['trusted'] and report_untrused == False:
                    continue

                list_of_ciphers.append(entry['cipher'])

                # check if the advertised ciphers are not effectively RC4 Only
                # for firefox or incompatible with firefox
                if entry['cipher'] in firefox_ciphers:
                    # if this is first cipher and we already are getting RC4
                    # then it means that RC4 is preferred
                    FF_compat = True
                    if not 'RC4' in entry['cipher']:
                        RC4_Only_FF = False
                else:
                    temp_FF_incompat[entry['cipher']] = 1

                """ store the ciphers supported """
                if 'ADH' in entry['cipher'] or 'AECDH' in entry['cipher']:
                    ciphertypes += 1
                    name = "z:" + entry['cipher']
                    tempcipherstats[name] = 1
                    tempcipherstats['Insecure'] = 1
                elif 'AES128-GCM' in entry['cipher'] or 'AES256-GCM' in entry['cipher']:
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
                elif 'CHACHA20' in entry['cipher']:
                    if not CHACHA20:
                        ciphertypes += 1
                        CHACHA20 = True
                elif 'IDEA' in entry['cipher'] or 'SEED' in entry['cipher']:
                    ciphertypes += 1
                    name = "y:" + entry['cipher']
                    tempcipherstats[name] = 1
                else:
                    ciphertypes += 1
                    name = "z:" + entry['cipher']
                    tempcipherstats[name] = 1
                    tempcipherstats['Insecure'] = 1

                """ store key handshake methods """
                if 'ECDHE' in entry['cipher']:
                    ECDHE = True
                    temppfsstats[entry['pfs']] = 1
                elif 'DHE' in entry['cipher'] or 'EDH' in entry['cipher']:
                    DHE = True
                    temppfsstats[entry['pfs']] = 1
                elif 'AECDH' in entry['cipher']:
                    AECDH = True
                elif 'ADH' in entry['cipher']:
                    ADH = True
                elif 'ECDH' in entry['cipher']:
                    ECDH = True
                elif 'DH' in entry['cipher']:
                    DH = True
                else:
                    RSA = True

                """ save the key size """
                if 'ECDSA' in entry['cipher'] or 'ECDH-RSA' in entry['cipher']:
                    ECDSA = True
                    tempecckeystats[entry['pubkey'][0]] = 1
                elif 'DSS' in entry['cipher']:
                    tempdsakeystats[entry['pubkey'][0]] = 1
                elif 'AECDH' in entry['cipher'] or 'ADH' in entry['cipher']:
                    """ skip """
                else:
                    tempkeystats[entry['pubkey'][0]] = 1
                    if ECDSA:
                        dualstack = True

                if 'True' in entry['trusted'] and not 'ADH' in entry['cipher'] and not 'AECDH' in entry['cipher']:
                    trusted = True

                """ save key signatures size """
                tempsigstats[entry['sigalg'][0]] = 1

                """ save tls ticket hint """
                if 'ticket_hint' in entry:
                    tempticketstats[entry['ticket_hint']] = 1

                """ check if OCSP stapling is supported """
                if 'ocsp_stapling' in entry:
                    if entry['ocsp_stapling'] == 'True':
                        ocsp_stapling=True
                    else:
                        ocsp_stapling=False

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

        """ don't store stats from unusued servers """
        if report_untrused == False and trusted == False:
            continue

        total += 1

        """ done with this file, storing the stats """
        if DHE or ECDHE:
            pfsstats['Support PFS'] += 1
            if 'DHE-' in results['ciphersuite'][0]['cipher']:
                pfsstats['Prefer PFS'] += 1
                pfsstats['Prefer ' + results['ciphersuite'][0]['pfs']] += 1
            for s in temppfsstats:
                pfsstats[s] += 1

        for s in tempkeystats:
            keysize['RSA ' + s] += 1
        for s in tempecckeystats:
            keysize['ECDSA ' + s] += 1
        for s in tempdsakeystats:
            keysize['DSA ' + s] += 1

        if dualstack:
            dsarsastack += 1

        """ save cipher ordering """
        if 'serverside' in results:
            if results['serverside'] == "False":
                cipherordering['Client side'] += 1
            else:
                cipherordering['Server side'] += 1
        else:
            cipherordering['Unknown'] += 1

        """ simulate handshake with Firefox """
        if FF_compat:
            if 'serverside' in results and results['serverside'] == "False":
                for cipher in firefox_ciphers:
                    if cipher in list_of_ciphers:
                        FF_selected = cipher
                        if 'RC4' in cipher:
                            FF_RC4_Pref = True
                        break
            else:
                for cipher in list_of_ciphers:
                    if cipher in firefox_ciphers:
                        FF_selected = cipher
                        if 'RC4' in cipher:
                            FF_RC4_Pref = True
                        break

        for s in tempsigstats:
            sigalg[s] += 1

        if len(tempticketstats) == 1:
            for s in tempticketstats:
                tickethint[s + " only"] += 1
        for s in tempticketstats:
            tickethint[s] += 1

        if ocsp_stapling is None:
            ocspstaple['Unknown'] += 1
        elif ocsp_stapling:
            ocspstaple['Supported'] += 1
        else:
            ocspstaple['Unsupported'] += 1

        """ store cipher stats """
        if AESGCM:
            cipherstats['AES-GCM'] += 1
            if ciphertypes == 1:
                cipherstats['AES-GCM Only'] += 1
        if AES:
            cipherstats['AES'] += 1
            if ciphertypes == 1:
                cipherstats['AES-CBC Only'] += 1
        if (AES and ciphertypes == 1) or (AESGCM and ciphertypes == 1)\
            or (AES and AESGCM and ciphertypes == 2):
                cipherstats['AES Only'] += 1
        if CHACHA20:
            cipherstats['CHACHA20'] += 1
            if ciphertypes == 1:
                cipherstats['CHACHA20 Only'] += 1
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
            if 'RC4' in results['ciphersuite'][0]['cipher']:
                if 'TLSv1.1' in results['ciphersuite'][0]['protocols'] or\
                   'TLSv1.2' in results['ciphersuite'][0]['protocols']:
                        cipherstats['RC4 forced in TLS1.1+'] += 1
                cipherstats['RC4 Preferred'] += 1

        if FF_compat:
            if 'ECDHE' in FF_selected:
                FF_selected_cipherstats['x:ECDHE'] += 1
            elif 'DHE' in FF_selected or 'EDH' in FF_selected:
                FF_selected_cipherstats['x:DHE'] += 1
            else:
                FF_selected_cipherstats['x:kRSA'] += 1
            FF_selected_cipherstats[FF_selected] += 1
            if RC4_Only_FF and ciphertypes != 1:
                cipherstats['x:FF 29 RC4 Only'] += 1
                for cipher in temp_FF_incompat:
                    FF_RC4_Only_cipherstats[cipher] += 1
            if FF_RC4_Pref and not 'RC4' in results['ciphersuite'][0]['cipher']:
                cipherstats['x:FF 29 RC4 Preferred'] += 1
                for cipher in temp_FF_incompat:
                    FF_RC4_preferred_cipherstats[cipher] += 1
        else:
            cipherstats['x:FF 29 incompatible'] += 1
            for cipher in temp_FF_incompat:
                FF_incompatible_cipherstats[cipher] += 1

        for cipher in tempcipherstats:
            cipherstats[cipher] += 1

        """ store handshake stats """
        if AECDH:
            handshakestats['AECDH'] += 1
        if ADH:
            handshakestats['ADH'] += 1
        if ECDHE:
            handshakestats['ECDHE'] += 1
        if DHE:
            handshakestats['DHE'] += 1
        if DHE and ECDHE:
            handshakestats['ECDHE and DHE'] += 1
        if ECDH:
            handshakestats['ECDH'] += 1
        if DH:
            handshakestats['DH'] += 1
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
        if not SSL2 and (SSL3 or TLS1) and not TLS1_1 and not TLS1_2:
            protocolstats['SSL3 or TLS1 Only'] += 1
        if not SSL2 and not SSL3 and not TLS1:
            protocolstats['TLS1.1 or up Only'] += 1
        if TLS1_1:
            protocolstats['TLS1.1'] += 1
            if not SSL2 and not SSL3 and not TLS1 and not TLS1_2:
                protocolstats['TLS1.1 Only'] += 1
        if TLS1_2:
            protocolstats['TLS1.2'] += 1
            if not SSL2 and not SSL3 and not TLS1 and not TLS1_1:
                protocolstats['TLS1.2 Only'] += 1
        if TLS1_2 and not TLS1_1 and TLS1:
            protocolstats['TLS1.2, 1.0 but not 1.1'] += 1

    # for testing, break early
    #if total % 1999 == 0:
    #    break

""" The 'x:FF 29 RC4 Preferred' counts only sites that effectively prefer
    RC4 when using FF, to make reporting more readable, sum it with sites
    that do that for all ciphers"""

if "x:FF 29 RC4 Preferred" in cipherstats and "RC4 Preferred" in cipherstats:
    cipherstats['x:FF 29 RC4 Preferred'] += cipherstats['RC4 Preferred']

print("SSL/TLS survey of %i websites from Alexa's top 1 million" % total)
if report_untrused == False:
    print("Stats only from connections that did provide valid certificates")
    print("(or anonymous DH from servers that do also have valid certificate installed)\n")

""" Display stats """
print("\nSupported Ciphers         Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(cipherstats):
    percent = round(cipherstats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(cipherstats[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nCipher ordering           Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(cipherordering):
    percent = round(cipherordering[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(cipherordering[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nFF 29 selected ciphers        Count    Percent")
print("-----------------------------+---------+------")
for stat in sorted(FF_selected_cipherstats):
    percent = round(FF_selected_cipherstats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(30) + " " + str(FF_selected_cipherstats[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nFF 29 RC4 Only other ciphers  Count    Percent")
print("-----------------------------+---------+------")
for stat in sorted(FF_RC4_Only_cipherstats):
    percent = round(FF_RC4_Only_cipherstats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(30) + " " + str(FF_RC4_Only_cipherstats[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nFF 29 RC4 pref other ciphers  Count    Percent")
print("-----------------------------+---------+------")
for stat in sorted(FF_RC4_preferred_cipherstats):
    percent = round(FF_RC4_preferred_cipherstats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(30) + " " + str(FF_RC4_preferred_cipherstats[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nFF 29 incompatible ciphers    Count    Percent")
print("-----------------------------+---------+------")
for stat in sorted(FF_incompatible_cipherstats):
    percent = round(FF_incompatible_cipherstats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(30) + " " + str(FF_incompatible_cipherstats[stat]).ljust(10) + str(percent).ljust(4) + "\n")

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

print("\nTLS session ticket hint   Count     Percent ")
print("-------------------------+---------+--------")
for stat in natural_sort(tickethint):
    percent = round(tickethint[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(tickethint[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nCertificate sig alg     Count     Percent ")
print("-------------------------+---------+--------")
for stat in sorted(sigalg):
    percent = round(sigalg[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(sigalg[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nCertificate key size    Count     Percent ")
print("-------------------------+---------+--------")
for stat in sorted(keysize):
    percent = round(keysize[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(keysize[stat]).ljust(10) + str(percent).ljust(9) + "\n")

sys.stdout.write("RSA/ECDSA Dual Stack".ljust(25) + " " + str(dsarsastack).ljust(10) + str(round(dsarsastack/total * 100, 4)) + "\n")

print("\nOCSP stapling             Count     Percent ")
print("-------------------------+---------+--------")
for stat in sorted(ocspstaple):
    percent = round(ocspstaple[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(ocspstaple[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nSupported Protocols       Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(protocolstats):
    percent = round(protocolstats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(protocolstats[stat]).ljust(10) + str(percent).ljust(4) + "\n")
