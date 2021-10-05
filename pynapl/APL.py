"""Dyalog APL <> Python interface"""

from . import APLPyConnect
from . import IPC

import threading


def APL(debug=False, dyalog=None, forceTCP=False):
    """Start an APL interpreter

    If `dyalog_path` is set, this is taken to be the path to the Dyalog interpreter.
    If it is not, a suitable Dyalog APL interpreter will be searched for on the
    path (on Unix/Linux) or in the registry (on Windows).
    """
    return APLPyConnect.Connection.APLClient(
        DEBUG=debug,
        dyalog=dyalog,
        forceTCP=forceTCP,
    )


def client(inp, outp, threaded=True):
    """Allow an APL interpreter to connect to the running Python instance.

    This is probably only useful for interactive sessions, as the APL instance
    will need to be started first, and its port number given to this function.

    As the APL side will be in control, you will not be able to access APL
    from Python.

    Interrupt handling will _not work_.
    """

    def run():
        if inp.lower() == 'tcp':
            # 'outp' should be a port number
            sock = IPC.TCPIO()
            sock.connect('localhost', int(outp))
            conn = APLPyConnect.Connection(sock, sock)
        else:
            # Open two pipes.
            i_f = IPC.FIFO(inp)
            i_f.openRead()
            o_f = IPC.FIFO(outp)
            o_f.openWrite()
            conn = APLPyConnect.Connection(i_f, o_f)

        conn.runUntilStop()

    if threaded:
        threading.Thread(target=run).start()
    else:
        run()
