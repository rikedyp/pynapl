# IPC

# On Linux, this is implemented with mkfifo
# On Windows, we use named pipes

import platform
import os
import select
import socket
import tempfile

from abc import ABC, abstractmethod
from typing import Type


class FIFOBaseClass(ABC):
    @abstractmethod
    def avail(self, timeout: float):
        raise NotImplementedError()

    @abstractmethod
    def read(self, length: int) -> str:
        raise NotImplementedError()

    @abstractmethod
    def write(self, data: str):
        raise NotImplementedError()

    @abstractmethod
    def close(self):
        raise NotImplementedError()

    @abstractmethod
    def flush(self):
        raise NotImplementedError()

    def openRead(self): raise NotImplementedError()
    def openWrite(self): raise NotImplementedError()


class TCPIO(FIFOBaseClass):
    sock=None
    sockfile=None 
    srvsock=None 

    def connect(self, host: str, port: int):
        # Attempt an IPV6 socket first
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.connect((host,port))
        except:
            # try an IPV4 socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host,port))

        self.sock = sock
        self.sockfile = sock.makefile('rwb')

    def startServer(self):
        self.srvsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srvsock.bind(('localhost', 0))
        _, port = self.srvsock.getsockname()
        self.srvsock.listen(1)
        return port 
        
    def acceptConnection(self): 
        self.sock, _ = self.srvsock.accept()
        self.sockfile = self.sock.makefile('rwb') 
        
    def avail(self,timeout):
        return bool(select.select([self.sock], [], [], timeout)[0])
    
    def read(self,amount):
        return self.sockfile.read(amount) 
        
    def write(self,data):
        return self.sockfile.write(data)
    
    def close(self):
        if self.sock is None or self.sockfile is None: return
        self.sockfile.close()
        self.sockfile=self.sock=None 
        
    def flush(self):
        self.sockfile.flush()


class UnixFIFO(FIFOBaseClass):
    fileobj = None
    name = None
    mode = None

    def __init__(self, name=None):
        if name==None:
            # make one
            name = tempfile.mktemp()
            os.mkfifo(name, 0o600)

        self.name=name

    def avail(self,timeout):
        return bool(select.select([self.fileobj], [], [], timeout)[0])

    def read(self, amount):
        inp = self.fileobj.read(amount)

        # this is necessary in Python 2 for some reason
        if len(inp)==0:
            # eof? shouldn't happen, reopen the file
            self.fileobj = open(self.name, self.mode)
            inp = self.read(amount)

        return inp

    def write(self, data):
        self.fileobj.write(data)

    def openRead(self):
        self.mode = 'rb'
        self.fileobj = open(self.name, self.mode)

    def openWrite(self):
        self.mode = 'wb'
        self.fileobj = open(self.name, self.mode)

    def close(self):
        if not self.fileobj is None:
            self.fileobj.close()
        self.fileobj = None
    
    def flush(self):
        self.fileobj.flush()

    def __del__(self):
        self.close()


FIFO: Type[FIFOBaseClass]
if os.name == "nt" or "CYGWIN" in platform.system():
    FIFO = TCPIO
elif os.name == "posix":
    FIFO = UnixFIFO
else:
    raise RuntimeError("Unsupported OS")
