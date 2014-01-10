#!/usr/bin/env python

path = "./results/"

import json
import sys
from collections import defaultdict
import os

stats = defaultdict(int)

for r,d,flist in os.walk(path):
    for f in flist:
        f_abs = os.path.join(r,f)
        with open(f_abs) as json_file:
            AES = False
            DESCBC3 = False
            RC4SHA = False
            RC4MD5 = False
            ECDHE = False
            GCM = False
            SSL2 = False
            SSL3 = False
            TLS1 = False
            TLS1_1 = False
            TLS1_2 = False
            stats['sites'] += 1
            results = json.load(json_file)
            if len(results['ciphersuite']) < 1:
                stats['broken'] += 1
                continue
            for entry in results['ciphersuite']:
                if 'AES' in entry['cipher']:
                    AES = True
                if 'DES-CBC3' in entry['cipher']:
                    DESCBC3 = True
                if 'RC4-SHA' == entry['cipher']:
                    RC4SHA = True
                if 'RC4-MD5' == entry['cipher']:
                    RC4MD5 = True
                if 'ECDHE' in entry['cipher']:
                    ECDHE = True
                if 'GCM' in entry['cipher']:
                    GCM = True
                for protocol in entry['protocols']:
                    if protocol == 'SSLv2':
                        SSL2 = True
                    if protocol == 'SSLv3':
                        SSL3 = True
                    if protocol == 'TLSv1':
                        TLS1 = True
                    if protocol == 'TLSv1.1':
                        TLS1_1 = True
                    if protocol == 'TLSv1.2':
                        TLS1_2 = True
            if 'DHE' in results['ciphersuite'][0]['cipher']:
                stats['PFS-FIRST'] += 1
            if AES:
                stats['AES'] += 1
            if DESCBC3:
                stats['DES-CBC3'] += 1
            if RC4SHA:
                stats['RC4-SHA'] += 1
            if RC4MD5:
                stats['RC4-MD5'] += 1
            if ECDHE:
                stats['ECDHE'] += 1
            if GCM:
                stats['AES-GCM'] += 1
            if not AES and not DESCBC3 and (RC4SHA or RC4MD5):
                stats['RC4-ONLY'] += 1
            if SSL2:
                stats['SSL2'] += 1
            if SSL3:
                stats['SSL3'] += 1
            if TLS1:
                stats['TLS1'] += 1
            if TLS1_1:
                stats['TLS1_1'] += 1
            if TLS1_2:
                stats['TLS1_2'] += 1
        json_file.close()
        if stats['sites'] % 2000 == 0:
            print stats
