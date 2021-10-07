# Utility functions

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

from functools import reduce


import operator
import signal

def product(seq):
    """The product of a sequence of numbers"""
    return reduce(operator.__mul__, seq, 1) 

def scan_reverse(f, arr):
    """Scan over a list in reverse, using a function"""
    r=list(arr)
    for i in reversed(range(len(r))[1:]):
        r[i-1] = f(r[i-1],r[i])
    return r

def extend(arr,length):
    """Extend a list APL-style"""
    if len(arr) >= length: return arr[:length]
    else:
        r=arr[:]
        while length-len(r) >= len(arr):
            r.extend(arr)
        else:
            r.extend(arr[:length-len(r)])
        return r


class NoInterruptSignal:
    def __enter__(self):
        try:
            self.SIGINT_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
            self.in_main_thread = True
        except ValueError:
            self.in_main_thread = False

    def __exit__(self, *args):
        if self.in_main_thread:
            signal.signal(signal.SIGINT, self.SIGINT_handler)

        return False  # Make sure errors propagate outside the context manager.
