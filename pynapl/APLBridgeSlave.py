#!/usr/bin/env python

# This program will connect to the APL side,
# after which it will execute commands given to it.

import pathlib
import os
import signal
import sys
import threading

# Allow users to import things from the cwd, just like in a normal interactive session.
sys.path.insert(1, "")

# Make a distinction when this code is ran directly from Python or when called by APL.
# Proper packaging and installing will likely remove the need for the two alternatives.
try:
    from . import APLPyConnect
    from . import IPC
except ImportError:
    # Make sure Python can find the imports when not ran from the package directory.
    sys.path.insert(1, str(pathlib.Path(__file__).parent.parent))
    from pynapl import APLPyConnect
    from pynapl import IPC


def runSlave(inp: str, outp: str):
    print("Opening input file...")

    # Open the input first, then the output. APL does it in the same order
    # (i.e., it opens its output first, which is Python's input). If it is
    # done the other way around, it will block.

    if inp.lower() == 'tcp':
        # then 'outp' is a port number, connect to it.
        sock = IPC.TCPIO()
        sock.connect('localhost', int(outp))
        conn = APLPyConnect.Connection(infile=sock, outfile=sock)
    else:
        infile, outfile = IPC.UnixFIFO(inp), IPC.UnixFIFO(outp)
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
