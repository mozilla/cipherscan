#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Author: Julien Vehent [:ulfr] - 2013
# Contributors: Hubert Kario - 2014

from __future__ import division, print_function

path = "./results/"

import json
import sys
from collections import defaultdict
import operator
import os
import re

def natural_sort(l):
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
    return sorted(l, key = alphanum_key)

""" client config cipher simulation """
client_ciphers={}
""" list of ciphers offered by Firefox 29 by default """
client_ciphers['FF 29']=[
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

client_ciphers['FF 35']=[
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-ECDSA-AES128-SHA',
        'ECDHE-RSA-AES128-SHA',
        'ECDHE-RSA-AES256-SHA',
        'ECDHE-ECDSA-RC4-SHA',
        'ECDHE-RSA-RC4-SHA',
        'DHE-RSA-AES128-SHA',
        'DHE-DSS-AES128-SHA',
        'DHE-RSA-AES256-SHA',
        'AES128-SHA',
        'AES256-SHA',
        'DES-CBC3-SHA',
        'RC4-SHA',
        'RC4-MD5']

client_ciphers['FF 44']=[
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-ECDSA-AES128-SHA',
        'ECDHE-RSA-AES128-SHA',
        'ECDHE-RSA-AES256-SHA',
        'DHE-RSA-AES128-SHA',
        'DHE-RSA-AES256-SHA',
        'AES128-SHA',
        'AES256-SHA',
        'DES-CBC3-SHA']

report_untrused=False

cipherstats = defaultdict(int)

# stats about different client performance
# ciphers selected by them, unsupported, etc.
client_RC4_Only_cipherstats={}
client_RC4_preferred_cipherstats={}
client_3DES_Only_cipherstats={}
client_3DES_preferred_cipherstats={}
client_incompatible_cipherstats={}
client_selected_cipherstats={}
for client_name in client_ciphers:
    client_RC4_Only_cipherstats[client_name] = defaultdict(int)
    client_RC4_preferred_cipherstats[client_name] = defaultdict(int)
    client_3DES_Only_cipherstats[client_name] = defaultdict(int)
    client_3DES_preferred_cipherstats[client_name] = defaultdict(int)
    client_incompatible_cipherstats[client_name] = defaultdict(int)
    client_selected_cipherstats[client_name] = defaultdict(int)

cipherordering = defaultdict(int)
pfsstats = defaultdict(int)
protocolstats = defaultdict(int)
handshakestats = defaultdict(int)
keysize = defaultdict(int)
sigalg = defaultdict(int)
tickethint = defaultdict(int)
eccfallback = defaultdict(int)
eccordering = defaultdict(int)
ecccurve = defaultdict(int)
npn = defaultdict(int)
ocspstaple = defaultdict(int)
fallbacks = defaultdict(int)
intolerancies = defaultdict(int)
impl_families = defaultdict(int)
# array with indexes of fallback names for the matrix report
fallback_ids = defaultdict(int)
i=0
fallback_ids['big-SSLv3'] = i
i+=1
fallback_ids['big-TLSv1.0'] = i
i+=1
fallback_ids['big-TLSv1.1'] = i
i+=1
fallback_ids['big-TLSv1.2'] = i
i+=1
# padding space
fallback_ids[' '] = i
i+=1
fallback_ids['small-SSLv3'] = i
i+=1
fallback_ids['small-TLSv1.0-notlsext'] = i
i+=1
fallback_ids['small-TLSv1.0'] = i
i+=1
fallback_ids['small-TLSv1.1'] = i
i+=1
fallback_ids['small-TLSv1.2'] = i
i+=1
# 2nd padding space
fallback_ids['  '] = i
i+=1
fallback_ids['v2-small-SSLv3'] = i
i+=1
fallback_ids['v2-small-TLSv1.0'] = i
i+=1
fallback_ids['v2-small-TLSv1.1'] = i
i+=1
fallback_ids['v2-small-TLSv1.2'] = i
i+=1
fallback_ids['v2-big-TLSv1.2'] = i
i+=1
# 3rd padding space
fallback_ids['   '] = i
pfssigalgfallback = defaultdict(int)
pfssigalgs = defaultdict(int)
pfssigalgsordering = defaultdict(int)
compression = defaultdict(int)
renegotiation = defaultdict(int)
dsarsastack = 0
total = 0
for r,d,flist in os.walk(path):

    for f in flist:

        """ initialize variables for stats of the current site """
        temppfsstats = {}
        tempkeystats = {}
        tempecckeystats = {}
        tempdsakeystats = {}
        tempgostkeystats = {}
        tempsigstats = {}
        tempticketstats = {}
        tempeccfallback = "unknown"
        tempeccordering = "unknown"
        tempecccurve = {}
        tempnpn = {}
        tempfallbacks = {}
        tempintolerancies = {}
        tempimpl_families = {}
        """ supported ciphers by the server under scan """
        tempcipherstats = {}
        temppfssigalgordering = {}
        temppfssigalgfallback = {}
        temppfssigalgs = {}
        tempcompression = {}
        temprenegotiation = {}
        ciphertypes = 0
        AESGCM = False
        AESCBC = False
        AES = False
        CHACHA20 = False
        DES3 = False
        CAMELLIA = False
        RC4 = False
        GOST89_cipher = False
        """ variables to support handshake simulation for different clients """
        client_RC4_Only={}
        client_3DES_Only={}
        client_compat={}
        temp_client_incompat={}
        client_RC4_Pref={}
        client_3DES_Pref={}
        client_selected={}
        for client_name in client_ciphers:
            # the following depends on client_compat, so by default it can be True
            client_RC4_Only[client_name]=True
            client_3DES_Only[client_name]=True
            client_compat[client_name]=False
            temp_client_incompat[client_name]={}
            client_RC4_Pref[client_name]=None
            client_3DES_Pref[client_name]=None
            client_selected[client_name]=None

        """ server side list of supported ciphers """
        list_of_ciphers = []
        ADH = False
        DHE = False
        AECDH = False
        ECDHE = False
        RSA = False
        ECDH = False
        DH = False
        GOST2001_kex = False
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
                # if there are no results from regular scan but there are
                # from fallback attempts that means that the scan of a host
                # is inconclusive
                if 'configs' in results:
                    tolerance = [' '] * len(fallback_ids)
                    for entry in results['configs']:
                        config = results['configs'][entry]
                        if config['tolerant'] == "True" and \
                                config['trusted'] == "True":

                            # save which protocols passed
                            if entry in fallback_ids:
                                tolerance[fallback_ids[entry]] = 'v'
                            else:
                                fallback_ids[entry] = len(fallback_ids)
                                tolerance.insert(fallback_ids[entry], 'v')

                    # analysis of host won't be continued, so we have to add
                    # results to the permanent, not temporary table, but
                    # do that only when there actually were detected values
                    if "".join(tolerance).strip():
                        fallbacks["".join(tolerance).rstrip()] += 1
                continue

            """ save ECC fallback (new format) """
            if 'curves_fallback' in results:
                tempeccfallback = results['curves_fallback']

            """ save ECC curve stats (old format) """
            if 'curve_fallback' in results:
                tempeccfallback = results['curve_fallback']
            if 'curve_ordering' in results:
                tempeccordering = results['curve_ordering']
            if 'curve' in results:
                for curve in results['curve']:
                    tempecccurve[curve] = 1
                if len(results['curve']) == 1:
                    tempecccurve[curve + ' Only'] = 1

            """ collect TLSv1.2 PFS ciphersuite sigalgs """
            if 'sigalgs' in results:
                if results['sigalgs']['ordering']:
                    temppfssigalgordering[results['sigalgs']['ordering']] = 1
                if results['sigalgs']['ECDSA-fallback']:
                    temppfssigalgfallback['ECDSA ' + results['sigalgs']['ECDSA-fallback']] = 1
                if results['sigalgs']['RSA-fallback']:
                    temppfssigalgfallback['RSA ' + results['sigalgs']['RSA-fallback']] = 1
                if 'RSA' in results['sigalgs'] and results['sigalgs']['RSA'][0] != 'Fail':
                    for pfssigalg in results['sigalgs']['RSA']:
                        temppfssigalgs['RSA-' + pfssigalg]=1
                    if len(results['sigalgs']['RSA']) == 1:
                        temppfssigalgs['RSA-' + results['sigalgs']['RSA'][0] + ' Only'] = 1
                if 'ECDSA' in results['sigalgs'] and results['sigalgs']['ECDSA'][0] != 'Fail':
                    for pfssigalg in results['sigalgs']['ECDSA']:
                        temppfssigalgs['ECDSA-' + pfssigalg]=1
                    if len(results['sigalgs']['ECDSA']) == 1:
                        temppfssigalgs['ECDSA-' + results['sigalgs']['ECDSA'][0] + ' Only'] = 1

            if 'configs' in results:
                tolerance = [' '] * len(fallback_ids)
                for entry in results['configs']:
                    config = results['configs'][entry]

                    if not entry in fallback_ids:
                        fallback_ids[entry] = len(fallback_ids)
                        tolerance.insert(fallback_ids[entry], ' ')

                    if config['tolerant'] == "True":
                        tolerance[fallback_ids[entry]] = 'v'
                    else:
                        tolerance[fallback_ids[entry]] = 'X'
                tempfallbacks["".join(tolerance).rstrip()] = 1
                configs = results['configs']
                try:
                    if configs['big-TLSv1.1']['tolerant'] != "True" and \
                            configs['big-TLSv1.2']['tolerant'] != "True" and \
                            configs['small-TLSv1.1']['tolerant'] != "True" and \
                            configs['small-TLSv1.2']['tolerant'] != "True":
                        if configs['v2-small-TLSv1.1']['tolerant'] != "True" and \
                                configs['v2-small-TLSv1.2']['tolerant'] != "True":
                            tempfallbacks['TLSv1.1+ strict Intolerance'] = 1
                        else:
                            tempfallbacks['TLSv1.1+ Intolerant'] = 1
                    if configs['big-TLSv1.1']['tolerant'] == "True" and \
                            configs['big-TLSv1.2']['tolerant'] != "True" and \
                            configs['small-TLSv1.1']['tolerant'] == "True" and \
                            configs['small-TLSv1.2']['tolerant'] != "True":
                        if configs['v2-small-TLSv1.2']['tolerant'] != "True":
                            tempfallbacks['TLSv1.2 strict Intolerance'] = 1
                        else:
                            tempfallbacks['TLSv1.2 Intolerant'] = 1
                    if configs['big-TLSv1.2']['tolerant'] != "True" and \
                            configs['big-TLSv1.1']['tolerant'] == "True" and \
                            configs['small-TLSv1.2']['tolerant'] == "True":
                        tempfallbacks['TLSv1.2 big Intolerance'] = 1
                    if configs['big-TLSv1.2']['tolerant'] != "True" and \
                            configs['small-TLSv1.0']['tolerant'] != "True" and \
                            configs['small-TLSv1.0-notlsext']['tolerant'] == "True":
                        tempfallbacks['TLS extension Intolerance'] = 1
                    if configs['big-TLSv1.2']['tolerant'] != "True" and \
                            configs['big-TLSv1.1']['tolerant'] != "True" and \
                            configs['big-TLSv1.0']['tolerant'] != "True" and \
                            (configs['small-TLSv1.2']['tolerant'] == "True" or
                                    configs['v2-small-TLSv1.2']['tolerant'] == "True"):
                        tempfallbacks['Big handshake intolerance'] = 1
                except KeyError:
                    pass

            if 'intolerancies' in results:
                intoler = results['intolerancies']
                for name, val in intoler.items():
                    if val is True:
                        tempintolerancies[name] = 1
                intol = [x.replace(' ', '_')
                              for x in tempintolerancies.keys()]
                all_above_tls_1_2 = ('TLS_1.3', 'TLS_1.4', 'SSL_3.254',
                                     'SSL_4.0', 'SSL_4.3', 'SSL_255.255')
                if all(i in intol for i in all_above_tls_1_2):
                    for i in all_above_tls_1_2:
                        intol.remove(i)
                    intol.append('TLS_1.3+')
                all_above_ssl_4_0 = ('SSL_4.3', 'SSL_4.0', 'SSL_255.255')
                if all(i in intol for i in all_above_ssl_4_0):
                    for i in all_above_ssl_4_0:
                        intol.remove(i)
                    intol.append("SSL_4.0+")
                if intol:
                    intol.sort(reverse=True)
                    tempimpl_families[" ".join(intol)] = 1
            else:
                tempintolerancies['x:missing information'] = 1

            """ get some extra data about server """
            if 'renegotiation' in results:
                temprenegotiation[results['renegotiation']] = 1

            if 'compression' in results:
                tempcompression[results['compression']] = 1

            """ loop over list of ciphers """
            for entry in results['ciphersuite']:

                # some servers return different certificates with different
                # ciphers, also we may become redirected to other server with
                # different config (because over-reactive IPS)
                if 'False' in entry['trusted'] and report_untrused == False:
                    continue

                list_of_ciphers.append(entry['cipher'])

                # check if the advertised ciphers are not effectively RC4 Only
                # for clients or incompatible with them
                for client_name in client_ciphers:
                    if entry['cipher'] in client_ciphers[client_name]:
                        # if this is first cipher and we already are getting RC4
                        # then it means that RC4 is preferred (and client is
                        # compatible with server)
                        client_compat[client_name]=True
                        if not 'RC4' in entry['cipher']:
                            client_RC4_Only[client_name] = False
                        if not 'CBC3' in entry['cipher']:
                            client_3DES_Only[client_name] = False
                    else:
                        temp_client_incompat[client_name][entry['cipher']] = 1

                """ store the ciphers supported """
                if 'ADH' in entry['cipher'] or 'AECDH' in entry['cipher'] or \
                        'EXP' in entry['cipher'] or \
                        'DES-CBC3-MD5' in entry['cipher'] or \
                        'RC4-64-MD5' in entry['cipher'] or \
                        'IDEA-CBC-MD5' in entry['cipher']:
                    ciphertypes += 1
                    name = "z:" + entry['cipher']
                    tempcipherstats[name] = 1
                    tempcipherstats['Insecure'] = 1
                elif 'AES128-GCM' in entry['cipher'] or 'AES256-GCM' in entry['cipher']:
                    if not AESGCM:
                        AES = True
                        AESGCM = True
                        ciphertypes += 1
                elif 'AES' in entry['cipher']:
                    if not AESCBC:
                        AES = True
                        AESCBC = True
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
                elif 'GOST89-GOST89' in entry['cipher']:
                    GOST89_cipher = True
                    ciphertypes += 1
                    name = "y:" + entry['cipher']
                    tempcipherstats[name] = 1
                else:
                    ciphertypes += 1
                    name = "z:" + entry['cipher']
                    tempcipherstats[name] = 1
                    tempcipherstats['Insecure'] = 1

                """ store key handshake methods """
                if 'EXP' in entry['cipher']:
                    pass
                elif 'AECDH' in entry['cipher']:
                    AECDH = True
                elif 'ADH' in entry['cipher']:
                    ADH = True
                elif 'ECDHE' in entry['cipher']:
                    ECDHE = True
                    temppfsstats[entry['pfs']] = 1
                elif 'DHE' in entry['cipher'] or 'EDH' in entry['cipher']:
                    DHE = True
                    temppfsstats[entry['pfs']] = 1
                elif 'ECDH' in entry['cipher']:
                    ECDH = True
                elif 'DH' in entry['cipher']:
                    DH = True
                elif entry['cipher'].startswith('GOST2001'):
                    GOST2001_kex = True
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
                elif 'GOST' in entry['cipher']:
                    tempgostkeystats[entry['pubkey'][0]] = 1
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

                # save NPN protocols supported
                if 'npn' in entry:
                    for proto in entry['npn']:
                        tempnpn[proto] = 1
                    if len(entry['npn']) == 1:
                        tempnpn[proto + ' Only'] = 1

                """ save ECC curves stats """
                if 'curves_ordering' in entry:
                    tempeccordering = entry['curves_ordering']
                if 'curves' in entry:
                    for curve in entry['curves']:
                        tempecccurve[curve] = 1
                    if len(entry['curves']) == 1:
                        tempecccurve[curve + ' Only'] = 1

        json_file.close()

        """ don't store stats from unusued servers """
        if report_untrused == False and trusted == False:
            continue

        total += 1

        """ done with this file, storing the stats """
        if DHE or ECDHE:
            pfsstats['Support PFS'] += 1
            if 'DHE-' in results['ciphersuite'][0]['cipher'] or \
                    'EDH-' in results['ciphersuite'][0]['cipher']:
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
        for s in tempgostkeystats:
            keysize['GOST ' + s] += 1

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

        """ simulate handshake with clients """
        for client_name in client_ciphers:
            if client_compat[client_name]:
                if 'serverside' in results and results['serverside'] == "False":
                    for cipher in client_ciphers[client_name]:
                        if cipher in list_of_ciphers:
                            client_selected[client_name] = cipher
                            if 'RC4' in cipher:
                                client_RC4_Pref[client_name] = True
                            if 'CBC3' in cipher:
                                client_3DES_Pref[client_name] = True
                            break
                else:
                    for cipher in list_of_ciphers:
                        if cipher in client_ciphers[client_name]:
                            client_selected[client_name] = cipher
                            if 'RC4' in cipher:
                                client_RC4_Pref[client_name] = True
                            if 'CBC3' in cipher:
                                client_3DES_Pref[client_name] = True
                            break

        for s in tempfallbacks:
            fallbacks[s] += 1

        for s in tempintolerancies:
            intolerancies[s] += 1

        for s in tempimpl_families:
            impl_families[s] += 1

        for s in tempsigstats:
            sigalg[s] += 1

        for s in temprenegotiation:
            renegotiation[s] += 1

        for s in tempcompression:
            compression[s] += 1

        if len(tempticketstats) == 1:
            for s in tempticketstats:
                tickethint[s + " only"] += 1
        for s in tempticketstats:
            tickethint[s] += 1

        eccfallback[tempeccfallback] += 1
        eccordering[tempeccordering] += 1
        for s in tempecccurve:
            ecccurve[s] += 1

        for s in tempnpn:
            npn[s] += 1

        if ocsp_stapling is None:
            ocspstaple['Unknown'] += 1
        elif ocsp_stapling:
            ocspstaple['Supported'] += 1
        else:
            ocspstaple['Unsupported'] += 1

        for s in temppfssigalgfallback:
            pfssigalgfallback[s] += 1
        for s in temppfssigalgs:
            pfssigalgs[s] += 1
        for s in temppfssigalgordering:
            pfssigalgsordering[s] += 1

        """ store cipher stats """
        if AESGCM:
            cipherstats['AES-GCM'] += 1
            if ciphertypes == 1:
                cipherstats['AES-GCM Only'] += 1
        if AES:
            cipherstats['AES'] += 1
        if AESCBC:
            cipherstats['AES-CBC'] += 1
            if ciphertypes == 1:
                cipherstats['AES-CBC Only'] += 1
        if (AESCBC and ciphertypes == 1) or (AESGCM and ciphertypes == 1)\
            or (AESCBC and AESGCM and ciphertypes == 2):
                cipherstats['AES Only'] += 1
        if CHACHA20:
            cipherstats['CHACHA20'] += 1
            if ciphertypes == 1:
                cipherstats['CHACHA20 Only'] += 1
        if DES3:
            cipherstats['3DES'] += 1
            if ciphertypes == 1:
                cipherstats['3DES Only'] += 1
            if 'CBC3' in results['ciphersuite'][0]['cipher']:
                if 'TLSv1.1' in results['ciphersuite'][0]['protocols'] or\
                   'TLSv1.2' in results['ciphersuite'][0]['protocols']:
                        cipherstats['3DES forced in TLS1.1+'] += 1
                cipherstats['3DES Preferred'] += 1

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

        for client_name in client_ciphers:
            if client_compat[client_name]:
                if 'ECDHE' in client_selected[client_name]:
                    client_selected_cipherstats[client_name]['x:ECDHE'] += 1
                elif 'DHE' in client_selected[client_name] or \
                    'EDH' in client_selected[client_name]:
                        client_selected_cipherstats[client_name]['x:DHE'] += 1
                else:
                    client_selected_cipherstats[client_name]['x:kRSA'] += 1

                client_selected_cipherstats[client_name][client_selected[client_name]] += 1

                if client_RC4_Only[client_name]:
                    cipherstats['x:' + client_name + ' RC4 Only'] += 1
                    for cipher in temp_client_incompat[client_name]:
                        client_RC4_Only_cipherstats[client_name][cipher] += 1
                if client_RC4_Pref[client_name]:
                    cipherstats['x:' + client_name + ' RC4 Preferred'] += 1
                    for cipher in temp_client_incompat[client_name]:
                        client_RC4_preferred_cipherstats[client_name][cipher] += 1
                if client_3DES_Only[client_name]:
                    cipherstats['x:' + client_name + ' 3DES Only'] += 1
                    for cipher in temp_client_incompat[client_name]:
                        client_3DES_Only_cipherstats[client_name][cipher] += 1
                if client_3DES_Pref[client_name]:
                    cipherstats['x:' + client_name + ' 3DES Preferred'] += 1
                    for cipher in temp_client_incompat[client_name]:
                        client_3DES_preferred_cipherstats[client_name][cipher] += 1
            else:
                cipherstats['x:' + client_name + ' incompatible'] += 1
                for cipher in temp_client_incompat[client_name]:
                    client_incompatible_cipherstats[client_name][cipher] += 1

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
        if GOST2001_kex:
            handshakestats['GOST2001'] += 1
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
            if not TLS1 and not TLS1_1 and not TLS1_2:
                protocolstats['SSL3 or lower Only'] += 1
        if TLS1:
            protocolstats['TLS1'] += 1
            if not SSL2 and not SSL3 and not TLS1_1 and not TLS1_2:
                protocolstats['TLS1 Only'] += 1
            if not TLS1_1 and not TLS1_2:
                protocolstats['TLS1 or lower Only'] += 1
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

""" The 'x:' + client_name + ' RC4 Preferred' counts only sites that
    effectively prefer RC4 when using given client, to make reporting more
    readable, sum it with sites that do that for all ciphers"""

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

print("\nCLIENT specific statistics\n")

for client_name in client_ciphers:
    print("\n" + client_name + " selected ciphers        Count    Percent")
    print("-----------------------------+---------+------")
    for stat in sorted(client_selected_cipherstats[client_name]):
        percent = round(client_selected_cipherstats[client_name][stat] / total * 100, 4)
        sys.stdout.write(stat.ljust(30) + " " + str(client_selected_cipherstats[client_name][stat]).ljust(10) + str(percent).ljust(4) + "\n")

    print("\n" + client_name + " RC4 Only other ciphers  Count    Percent")
    print("-----------------------------+---------+------")
    for stat in sorted(client_RC4_Only_cipherstats[client_name]):
        percent = round(client_RC4_Only_cipherstats[client_name][stat] / total * 100, 4)
        sys.stdout.write(stat.ljust(30) + " " + str(client_RC4_Only_cipherstats[client_name][stat]).ljust(10) + str(percent).ljust(4) + "\n")

    print("\n" + client_name + " RC4 pref other ciphers  Count    Percent")
    print("-----------------------------+---------+------")
    for stat in sorted(client_RC4_preferred_cipherstats[client_name]):
        percent = round(client_RC4_preferred_cipherstats[client_name][stat] / total * 100, 4)
        sys.stdout.write(stat.ljust(30) + " " + str(client_RC4_preferred_cipherstats[client_name][stat]).ljust(10) + str(percent).ljust(4) + "\n")

    print("\n" + client_name + " incompatible ciphers    Count    Percent")
    print("-----------------------------+---------+------")
    for stat in sorted(client_incompatible_cipherstats[client_name]):
        percent = round(client_incompatible_cipherstats[client_name][stat] / total * 100, 4)
        sys.stdout.write(stat.ljust(30) + " " + str(client_incompatible_cipherstats[client_name][stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nSupported Handshakes      Count     Percent")
print("-------------------------+---------+-------")
for stat in sorted(handshakestats):
    percent = round(handshakestats[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(handshakestats[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nSupported NPN protocols   Count    Percent ")
print("-------------------------+---------+--------")
for name, val in sorted(npn.items()):
    percent = round(val / total * 100, 4)
    sys.stdout.write(name.ljust(25) + " " + str(val).ljust(10) + str(percent).ljust(9) + "\n")

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

print("\nSupported ECC curves      Count     Percent ")
print("-------------------------+---------+--------")
for stat in sorted(ecccurve):
    percent = round(ecccurve[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(ecccurve[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nUnsupported curve fallback     Count     Percent ")
print("------------------------------+---------+--------")
for stat in sorted(eccfallback):
    percent = round(eccfallback[stat] / total * 100,4)
    sys.stdout.write(stat.ljust(30) + " " + str(eccfallback[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nECC curve ordering        Count     Percent ")
print("-------------------------+---------+--------")
for stat in sorted(eccordering):
    percent = round(eccordering[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(eccordering[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nTLSv1.2 PFS supported sigalgs  Count     Percent ")
print("------------------------------+---------+--------")
for stat in sorted(pfssigalgs):
    percent = round(pfssigalgs[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(30) + " " + str(pfssigalgs[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nTLSv1.2 PFS ordering           Count     Percent ")
print("------------------------------+---------+--------")
for stat in sorted(pfssigalgsordering):
    percent = round(pfssigalgsordering[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(30) + " " + str(pfssigalgsordering[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nTLSv1.2 PFS sigalg fallback    Count     Percent ")
print("------------------------------+---------+--------")
for stat in sorted(pfssigalgfallback):
    percent = round(pfssigalgfallback[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(30) + " " + str(pfssigalgfallback[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nRenegotiation             Count     Percent ")
print("-------------------------+---------+--------")
for stat in natural_sort(renegotiation):
    percent = round(renegotiation[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(renegotiation[stat]).ljust(10) + str(percent).ljust(9) + "\n")

print("\nCompression               Count     Percent ")
print("-------------------------+---------+--------")
for stat in natural_sort(compression):
    percent = round(compression[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(25) + " " + str(compression[stat]).ljust(10) + str(percent).ljust(9) + "\n")

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

if total == 0:
    total = 1
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

print("\nRequired fallbacks                       Count     Percent")
print("----------------------------------------+---------+-------")
print("big  small v2   ")
print("----+-----+-----+------------------------+---------+-------")
for stat in sorted(fallbacks):
    percent = round(fallbacks[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(40) + " " + str(fallbacks[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nFallback column names")
print("------------------------")
fallback_ids_sorted=sorted(fallback_ids.items(), key=operator.itemgetter(1))
for touple in fallback_ids_sorted:
    print(str(touple[1]+1).rjust(3) + "  " + str(touple[0]))

print("\nClient Hello intolerance                 Count     Percent")
print("----------------------------------------+---------+-------")
for stat in natural_sort(intolerancies):
    percent = round(intolerancies[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(40) + " " + str(intolerancies[stat]).ljust(10) + str(percent).ljust(4) + "\n")

print("\nImplementation families                               Count       Percent")
print("-----------------------------------------------------+-----------+-------")
for stat in natural_sort(impl_families):
    percent = round(impl_families[stat] / total * 100, 4)
    sys.stdout.write(stat.ljust(50) + " " + str(impl_families[stat]).ljust(10) + str(percent).ljust(4) + "\n")
