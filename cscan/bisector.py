# Copyright (c) 2015 Hubert Kario <hkario@redhat.com>
# Released under Mozilla Public License Version 2.0

"""Find an itolerance through bisecting Client Hello"""

import copy
from tlslite.extensions import PaddingExtension

def list_union(first, second):
    """Return an union between two lists, preserving order"""
    first_i = iter(first)
    second_i = iter(second)
    first_s = set(first)
    second_s = set(second)

    ret = []
    first_el = next(first_i, None)
    second_el = next(second_i, None)
    while first_el is not None and second_el is not None:
        if first_el != second_el:
            if first_el in second_s and second_el in first_s:
                # the second list is longer, so take from it
                ret.append(second_el)
                # no discard as we would have duplicates
                second_el = next(second_i, None)
                continue
            if first_el not in second_s:
                ret.append(first_el)
                first_s.discard(first_el)
                first_el = next(first_i, None)
            if second_el not in first_s:
                ret.append(second_el)
                second_s.discard(second_el)
                second_el = next(second_i, None)
        else:
            ret.append(first_el)
            first_s.discard(first_el)
            second_s.discard(first_el)
            first_el = next(first_i, None)
            second_el = next(second_i, None)
    while first_el:
        if first_el not in second_s:
            ret.append(first_el)
        first_el = next(first_i, None)
    while second_el:
        if second_el not in first_s:
            ret.append(second_el)
        second_el = next(second_i, None)
    return ret


def bisect_lists(first, second):
    """Return a list that is in the "middle" between the given ones"""
    # handle None special cases
    if first is None and second is None:
        return None
    if first is not None and second is None:
        first, second = second, first
    if first is None and second is not None:
        if len(second) == 0:
            return None
        elif len(second) == 1:
            return []
        else:
            first = []
    # make the second lists always the longer one
    if len(first) > len(second):
        second, first = first, second
    first_s = set(first)
    second_s = set(second)
    union = list_union(first, second)
    symmetric_diff = first_s.symmetric_difference(second_s)
    # preserve order for the difference
    symmetric_diff = [x for x in union if x in symmetric_diff]
    half_diff = set(symmetric_diff[:len(symmetric_diff)//2])
    intersection = first_s & second_s

    return [x for x in union if x in half_diff or x in intersection]


def bisect_padding_extension(first, second):
    if first is None and second is None:
        return None
    if first is not None and second is None:
        first, second = second, first
    if first is None and second is not None:
        if len(second.paddingData) == 0:
            return None
        elif len(second.paddingData) == 1:
            return PaddingExtension()
        else:
            first = PaddingExtension()
    return PaddingExtension().create((len(first.paddingData) +
                                      len(second.paddingData)) // 2)


def bisect_extensions(first, second):
    # handle padding extension
    if first is None and second is None:
        return None
    if first is not None and second is None:
        first, second = second, first
    if first is None and second is not None:
        if len(second) == 0:
            return None
        if len(second) == 1:
            return []
        first = []
    f_ext = next((x for x in first if isinstance(x, PaddingExtension)), None)
    s_ext = next((x for x in second if isinstance(x, PaddingExtension)), None)

    ext = bisect_padding_extension(f_ext, s_ext)
    if ext is None:
        # remove the extension
        return [x for x in first if not isinstance(x, PaddingExtension)]
    else:
        if f_ext is None:
            return first + [ext]
        # replace extension
        return [ext if isinstance(x, PaddingExtension) else x for x in first]


def bisect_hellos(first, second):
    """Return a client hello that is in the "middle" of two other"""
    ret = copy.copy(first)

    ret.client_version = ((first.client_version[0] + second.client_version[0])
                          // 2,
                          (first.client_version[1] + second.client_version[1])
                          // 2)
    ret.cipher_suites = bisect_lists(first.cipher_suites, second.cipher_suites)
    ret.extensions = bisect_lists(first.extensions, second.extensions)
    ret.compression_methods = bisect_lists(first.compression_methods,
                                           second.compression_methods)
    if first.extensions == ret.extensions \
            or second.extensions == ret.extensions:
        ret.extensions = bisect_extensions(first.extensions,
                                           second.extensions)
    return ret

class Bisect(object):
    """
    Perform a bisection between two Client Hello's to find intolerance

    Tries to find a cause for intolerance by using a bisection-like
    algorithm
    """

    def __init__(self, good, bad, hostname, callback):
        """Set the generators for good and bad hello's and callback to test"""
        self.good = good
        self.bad = bad
        if hostname is not None:
            self.hostname = bytearray(hostname, 'utf-8')
        else:
            self.hostname = None
        self.callback = callback

    def run(self):
        good_hello = self.good(self.hostname)
        bad_hello = self.bad(self.hostname)
        middle = bisect_hellos(good_hello, bad_hello)

        while good_hello != middle and \
                middle != bad_hello:
            if self.callback(middle):
                good_hello = middle
            else:
                bad_hello = middle
            middle = bisect_hellos(good_hello, bad_hello)

        return (good_hello, bad_hello)
