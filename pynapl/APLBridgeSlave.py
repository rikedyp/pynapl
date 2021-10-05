#!/usr/bin/env python

# This program will connect to the APL side,
# after which it will execute commands given to it.

import os
import signal
import sys
import threading

from . import APLPyConnect
from . import IPC

# Allow users to import things from the cwd, just like in a normal interactive session.
sys.path.insert(1, "")


def runSlave(inp, outp):
    print("Opening input file...")

    # Open the input first, then the output. APL does it in the same order
    # (i.e., it opens its output first, which is Python's input). If it is
    # done the other way around, it will block.

    if inp.lower() == 'tcp':
        # then 'outp' is a port number, connect to it.
        infile = outfile = sock = IPC.TCPIO()
        sock.connect('localhost', int(outp))
    else:
        infile, outfile = IPC.FIFO(inp), IPC.FIFO(outp)
        infile.openRead()
        outfile.openWrite()

    conn = APLPyConnect.Connection(infile=infile, outfile=outfile)
    print("Connected.")
    conn.runUntilStop()
    sys.exit(0)


if __name__ == "__main__":
    if '--' in sys.argv:
        sys.argv = sys.argv[sys.argv.index('--'):]

    infile, outfile = sys.argv[1:3]

    setpgrp = getattr(os, "setpgrp", lambda: None)  # Only available on Unix.
    setpgrp()

    signal.signal(signal.SIGINT, signal.default_int_handler)

    if 'thread' in sys.argv:
        print("Starting thread")
        threading.Thread(target=lambda: runSlave(infile, outfile)).start()
    else:
        runSlave(infile, outfile)
