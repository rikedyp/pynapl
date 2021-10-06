"""
This module handles the passing of messages between the APL side and the Python side.
"""


import enum
import json
import os
import platform
import signal
import sys
import time
import types

from . import RunDyalog, Interrupt, WinDyalog, IPC
from .Array import APLArray
from .PyEvaluator import PyEvaluator
from .ObjectWrapper import ObjectStore, ObjectWrapper


# These fail when threaded, but that's OK
def ignoreInterrupts():
    try:
        return signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:
        pass


def allowInterrupts():
    try:
        return signal.signal(signal.SIGINT, signal.default_int_handler)
    except ValueError:
        pass


def setInterrupts(x):
    if x is None:
        return

    try:
        return signal.signal(signal.SIGINT, x)
    except ValueError:
        pass


class APLError(Exception):
    """Encapsulate an APL error message."""

    def __init__(self, message="", json_obj=None):
        self.dmx = None

        # If a JSON object is given, build the `message` from it.
        if json_obj is not None:
            if isinstance(json_obj, bytes):
                json_obj = json_obj.decode("utf-8")
            error_obj = json.loads(json_obj)
            message = error_obj["Message"]
            # Try giving more information about the error by inspecting DMX.
            self.dmx = error_obj.get("DMX", {})
            dmx_message = self.dmx.get("Message", "")
            if dmx_message:
                message += ": " + dmx_message

        if isinstance(message, bytes):
            # `message` might need decoding if it comes directly from the APL interface.
            message = message.decode("utf-8")

        super().__init__(message)


class MalformedMessage(Exception):
    """Exceptions raised when message format is wrong."""
    pass


class MessageType(enum.IntEnum):
    """The known message types."""

    OK = 0  # Sent as a response indicating success, but returning nothing else.
    PID = 1  # Initial connection message containing the PID.
    STOP = 2  # Indicates the desire to break the connection.
    REPR = 3  # Evaluates an expression and then returns its representation (for debug).
    EXEC = 4  # Executes statement(s) and returns OK or ERR
    REPR_RET = 5  # Return from REPR
    EVAL = 10  # Evaluate a Python expression, including arguments, with APL conversion.
    EVAL_RET = 11  # Returning the value of an EVAL message.
    DEBUG_SERIALISATION_ROUNDTRIP = 253
    ERR = 255  # Python error.


class Message:
    """A variable-length message to be sent to/from APL from/to Python.

    The message format is as follows:
     - the first byte contains the message type, as per the `MessageType` enum;
     - the 4 bytes that follow contain `size`, the data length in big-endian;
     - the remainder `size` bytes hold the body of the message.
    """

    MAX_LEN = 2 ** 32 - 1

    def __init__(self, type_, data):
        """An instance is created by providing a type and the data.

        The message type must be one of `MessageType` and the `data` can
        be a string or a bytes object, but both are saved as bytes.
        """

        if type_ not in MessageType:
            raise TypeError(f"Message type {type_} unknown.")
        self.type = type_

        if len(data) > Message.MAX_LEN:
            raise ValueError("Maximum body length exceeded.")
        self.data = data.encode("utf8") if isinstance(data, str) else data

    def send(self, writer):
        """Send a message using a writer"""

        # Turn off interrupt signal handler temporarily;
        # this fails under Python 3 if it happens during shutdown.
        # The workaround is to just ignore it in that case
        # the error claims SIG_IGN isn't a valid signal.
        try:
            s = signal.signal(signal.SIGINT, signal.SIG_IGN)
        except (TypeError, ValueError):
            s = None

        try:
            header = bytes([
                self.type,
                (len(self.data) & 0xFF000000) >> 24,
                (len(self.data) & 0x00FF0000) >> 16,
                (len(self.data) & 0x0000FF00) >> 8,
                (len(self.data) & 0x000000FF) >> 0,
            ])

            writer.write(header)
            writer.write(self.data)
            writer.flush()
        finally:
            if s:
                signal.signal(signal.SIGINT, s)

    @staticmethod
    def recv(reader,block=True):
        """Read a message from a reader.
        
        If block is set to False, then it will return None if no message is
        available, rather than wait until one comes in.
        """

        s = None
        setsgn = False
        
        try:
            if block:
                # wait for message available
                while True:
                    if reader.avail(0.1): break
            else:
                # if no message available, return None
                if not reader.avail(0.1): return None

                # once we've started reading, finish reading: turn off the interrupt handler
            try:
                s, setsgn = signal.signal(signal.SIGINT, signal.SIG_IGN), True
            except ValueError:
                pass # we're not on the main thread, so no signaling at all

            # read the header
            try:
                mtype = MessageType(ord(reader.read(1)))
                lfield = reader.read(4)
                length = (lfield[0]<<24) + (lfield[1]<<16) + (lfield[2]<<8) + lfield[3]
            except (TypeError, IndexError, ValueError):
                raise MalformedMessage("out of data while reading message header")

            # read the data
            try:
                data = reader.read(length)
            except ValueError:
                raise MalformedMessage("out of data while reading message body")

            if len(data) != length:
                raise MalformedMessage("out of data while reading message body")

            return Message(mtype, data)
        finally:
            # turn the interrupt handler back on if we'd turned it off
            if setsgn:
                signal.signal(signal.SIGINT, s)

        

class Connection(object):
    """A connection"""

    class APL(object):
        """Represents the APL interpreter."""

        pid=None
        DEBUG=False
        store=None

        def __init__(self, conn):
            self.store = ObjectStore()
            self.conn=conn
            self.ops=0 # keeps track of how many operators have been defined

        def obj(self, obj):
            """Wrap an object so it can be sent to APL."""
            return ObjectWrapper(self.store, obj) 
   
        def _access(self, ref):
            """Called by the APL side to access a Python object"""
            return self.store.retrieve(ref)

        def _release(self, ref):
            """Called by the APL side to release an object it has sent."""
            self.store.release(ref)

        def stop(self):
            """If the connection was initiated from the Python side, this will close it."""
            if not self.pid is None:
                # already killed it? (destructor might call this function after the user has called it as well)
                if not self.pid:
                    return
                try: Message(MessageType.STOP, "STOP").send(self.conn.outfile)
                except (ValueError, AttributeError): pass # if already closed, don't care
                
                # close the pipes
                try:
                    self.conn.infile.close()
                    self.conn.outfile.close()
                except:
                    pass # we're gone anyway

                # give the APL process half a second to exit cleanly
                time.sleep(.5)
                
         
                if not self.DEBUG:
                    try: os.kill(self.pid, 15) # SIGTERM
                    except OSError: pass # just leak the instance, it will be cleaned up once Python exits
                
                self.pid=0

            else: 
                raise ValueError("Connection was not started from the Python end.")

        def __del__(self):
            if self.pid: self.stop()

        def fn(self, aplfn, raw=False):
            """Expose an APL function to Python.

            The result will be considered niladic if called with no arguments,
            monadic if called with one and dyadic if called with two.
            
            If "raw" is set, the return value will be given as an APLArray rather
            than be converted to a 'suitable' Python representation.
            """

            if not type(aplfn) is str:
                aplfn = str(aplfn, "utf-8")

            def __fn(*args):
                if len(args)==0: return self.eval(aplfn, raw=raw)
                if len(args)==1: return self.eval("(%s)⊃∆"%aplfn, args[0], raw=raw)
                if len(args)==2: return self.eval("(⊃∆)(%s)2⊃∆"%aplfn, args[0], args[1], raw=raw)
                return APLError("Function must be niladic, monadic or dyadic.")

            # op can use this for an optimization
            __fn.aplfn = aplfn

            return __fn

        def op(self, aplop):
            """Expose an APL operator.

            It can be called with either 1 or 2 arguments, depending on whether the
            operator is monadic or dyadic. The arguments may be values or Python
            functions.

            If the Python function was created using apl.fn, this is recognized
            and the function is run in APL directly.
            """

            if not type(aplop) is str:
                aplop = str(aplop, "utf-8")

            def storeArgInWs(arg,nm):
                wsname = "___op%d_%s" % (self.ops, nm)

                if type(arg) is types.FunctionType \
                or type(arg) is types.BuiltinFunctionType:
                    # it is a function
                    if hasattr(arg,'__dict__') and 'aplfn' in arg.__dict__:
                        # it is an APL function
                        self.eval("%s ← %s⋄⍬" % (wsname, arg.aplfn))
                    else:
                        # it is a Python function
                        # store it under this name
                        self.__dict__[wsname] = arg
                        # make it available to APL
                        self.eval("%s ← (py.PyFn'APL.%s').Call⋄⍬" % (wsname, wsname))
                else:
                    # it is a value
                    self.eval("%s ← ⊃∆" % wsname, arg) 
                return wsname

            def __op(aa, ww=None, raw=False):
               

                # store the arguments into APL at the time that the operator is defined
                wsaa = storeArgInWs(aa, "aa")
               
                aplfn = "((%s)(%s))" % (wsaa, aplop)

                # . / ∘. must be special-cased
                if aplop in [".","∘."]: aplfn='(∘.(%s))' % wsaa

                if not ww is None: 
                    wsww = storeArgInWs(ww, "ww")
                    aplfn = "((%s)%s(%s))" % (wsaa, aplop, wsww)
                    # again, . / ∘. must be special-cased
                    if aplop in [".","∘."]: aplfn='((%s).(%s))' % (wsaa, wsww)
                
                def __fn(*args):
                    # an APL operator can't return a niladic function
                    if len(args)==0: raise APLError("A function derived from an APL operator cannot be niladic.")
                    if len(args)==1: return self.eval("(%s)⊃∆"%aplfn, args[0], raw=raw)
                    if len(args)==2: return self.eval("(⊃∆)(%s)2⊃∆"%aplfn, args[0], args[1], raw=raw)
                    raise APLError("Function must be monadic or dyadic.")

                __fn.aplfn = aplfn
                self.ops+=1
                return __fn
            

            return __op

        def interrupt(self):
            """Send a strong interrupt to the Dyalog interpreter."""
            if self.pid:
                Interrupt.interrupt(self.pid)

        def tradfn(self, tradfn):
            """Define a tradfn or tradop on the APL side.

            Input must be string, the lines of which will be passed to ⎕FX."""

            Message(MessageType.EXEC, tradfn).send(self.conn.outfile)
            reply = self.conn.expect(MessageType.OK)

            if reply.type == MessageType.ERR:
                raise APLError(json_obj=str(reply.data,'utf-8'))
            else:
                return self.fn(str(reply.data,'utf-8'))

        def repr(self, aplcode):
            """Run an APL expression, return string representation"""
            
            # send APL message
            Message(MessageType.REPR, aplcode).send(self.conn.outfile)
            reply = self.conn.expect(MessageType.REPR_RET)

            if reply.type == MessageType.ERR:
                raise APLError(json_obj=str(reply.data,'utf-8'))
            else:
                return reply.data

        def fix(self, code):
            """2⎕FIX an APL script. It will become available in the workspace.
               Input may be a string or a list."""

            # implemented using eval 
            if not type(code) is str: 
                code = str(code, 'utf-8')

            if not type(code) is list:
                code = code.split("\n") # luckily APL has no multiline strings
            
            return self.eval("2⎕FIX ∆", *code)
                
        def eval(self, aplexpr, *args, **kwargs):
            """Evaluate an APL expression. Any extra arguments will be exposed
               as an array ∆. If `raw' is set, the result is not converted to a
               Python representation."""
           
            if not type(aplexpr) is str:
                # this should be an UTF-8 string
                aplexpr=str(aplexpr, "utf8")

            # normalize (remove superfluous whitespace and newlines, add in ⋄s where
            # necessary)

            aplexpr = '⋄'.join(x.strip() for x in aplexpr.split("\n") if x.strip()) \
                         .replace('{⋄','{').replace('⋄}','}') \
                         .replace('(⋄','(').replace('⋄)',')')

            payload = APLArray.from_python([aplexpr, args], apl=self).toJSONString()
            Message(MessageType.EVAL, payload).send(self.conn.outfile)

            reply = self.conn.expect(MessageType.EVAL_RET)

            if reply.type == MessageType.ERR:
                raise APLError(json_obj=reply.data)

            answer = APLArray.fromJSONString(reply.data)

            if 'raw' in kwargs and kwargs['raw']:
                return answer
            else:
                return answer.to_python(self)

    @staticmethod
    def APLClient(DEBUG=False, dyalog=None, forceTCP=False):
        """Start an APL client. This function returns an APL instance."""
        
        # if on Windows, use TCP always
        if os.name=='nt' or 'CYGWIN' in platform.system():
            forceTCP=True 
       
        if forceTCP:
            # use TCP 
            inpipe = outpipe = IPC.TCPIO() # TCP connection is bidirectional
            outarg = 'TCP'
            inarg = str(inpipe.startServer())
        else:    
            # make two named pipes
            inpipe = IPC.FIFO()
            outpipe = IPC.FIFO()
            inarg = inpipe.name
            outarg = outpipe.name 
        
        if DEBUG:
            print("in: ",inarg)
            print("out: ",outarg)

        # start up Dyalog
        if not DEBUG: RunDyalog.dystart(outarg, inarg, dyalog=dyalog)

        if forceTCP:
            # wait for Python to make the connection 
            inpipe.acceptConnection()
        else: 
            # start the writer first
            outpipe.openWrite()
            inpipe.openRead()

        if DEBUG:print("Waiting for PID...")
        connobj = Connection(inpipe, outpipe, signon=False)

        # ask for the PID
        pidmsg = connobj.expect(MessageType.PID)
        
        if pidmsg.type==MessageType.ERR:
            raise APLError(pidmsg.data)
        else:
            pid=int(pidmsg.data)
            if DEBUG:print("Ok! pid=%d" % pid)
            apl = connobj.apl
            apl.pid = pid
            apl.DEBUG=DEBUG
            
            # if we are on Windows, hide the window
            if os.name=='nt': WinDyalog.hide(pid)
            
            return apl

    def __init__(self, infile, outfile, signon=True):
        self.infile=infile
        self.outfile=outfile
        self.apl = Connection.APL(self)
        self.isSlave = False
        if signon:
            Message(MessageType.PID, str(os.getpid())).send(self.outfile)
            self.isSlave = True

    def runUntilStop(self):
        """Receive messages and respond to them until STOP is received.
        """
        self.stop = False
        
        while not self.stop:
           
            sig = ignoreInterrupts()

            # is there a message available?
            msg = Message.recv(self.infile, block=False)

            setInterrupts(sig)

            if not msg is None:
                # yes, respond to it
                self.respond(msg)

    def expect(self, msgtype):
        """Expect a certain type of message. If such a message or an error
           is received, return it; if a different message is received, then
           handle it and go back to waiting for the right type of message."""
            
        while True: 
            s = None
            try:
                # only turn off interrupts if the APL side is in control
                if self.isSlave: s = ignoreInterrupts()
                msg = Message.recv(self.infile)

                if msg.type in (msgtype, MessageType.ERR):
                    return msg
                else:
                    if self.isSlave: allowInterrupts()
                    self.respond(msg)
            except KeyboardInterrupt:
                self.apl.interrupt()
            finally:
                if self.isSlave: setInterrupts(s)
                pass

    def respond(self, message):
        # Add ctrl+c signal handling
        try:
            self.respond_inner(message)
        except KeyboardInterrupt:
            # If there is an interrupt during 'respond', then that means
            # the Python side was interrupted, and we need to tell the
            # APL this.
            Message(MessageType.ERR, "Interrupt").send(self.outfile)

    def respond_inner(self, message):
        """Respond to a message"""
        
        t = message.type
        if t==MessageType.OK:
            # return 'OK' to such messages
            Message(MessageType.OK, message.data).send(self.outfile)

        elif t==MessageType.PID:
            # this is interpreted as asking for the PID
            Message(MessageType.PID, str(os.getpid())).send(self.outfile)
        
        elif t==MessageType.STOP:
            # send a 'STOP' back in acknowledgement and set the stop flag
            self.stop = True
            Message(MessageType.STOP, "STOP").send(self.outfile)
        
        elif t==MessageType.REPR:
            # evaluate the input and send the Python representation back
            try:
                val = repr(eval(message.data))
                Message(MessageType.REPR_RET, val).send(self.outfile)
            except Exception as e:
                Message(MessageType.ERR, repr(e)).send(self.outfile)

        elif t==MessageType.EXEC:
            # execute some Python code in the global context
            sig = None
            try:
                sig = allowInterrupts()

                script = message.data
                if type(script) is bytes:
                    script = str(script, 'utf-8')

                PyEvaluator.executeInContext(script, self.apl)
                Message(MessageType.OK, '').send(self.outfile)
            except Exception as e:
                Message(MessageType.ERR, repr(e)).send(self.outfile)
            finally:
                setInterrupts(sig)

        elif t==MessageType.EVAL:
            # evaluate a Python expression with optional arguments
            # expected input: APLArray, first elem = expr string, 2nd elem = arguments
            # output, if not an APLArray already, will be automagically converted

            sig = None
            try:
                sig = allowInterrupts()
                val = APLArray.fromJSONString(message.data)
                # unpack code
                if val.rho != [2]: 
                    raise MalformedMessage("EVAL expects a ⍴=2 array, but got: %s" % repr(val.rho))

                if not isinstance(val[[0]], APLArray):
                    raise MalformedMessage("First argument must contain code string.")

                code = val[[0]].to_python(self.apl)
                if not type(code) in (str,bytes):
                    raise MalformedMessage("Code element must be a string, but got: %s" % repr(code))

                # unpack arguments
                args = val[[1]]
                if not isinstance(val[[1]], APLArray) \
                or len(val[[1]].rho) != 1:
                    raise MalformedMessage("Argument list must be rank-1 array.")

                result = PyEvaluator(code, args, self).go().toJSONString()
                Message(MessageType.EVAL_RET, result).send(self.outfile)
            except Exception as e:
                #raise
                Message(MessageType.ERR, repr(e)).send(self.outfile)
            finally:
                setInterrupts(sig)


        elif t==MessageType.DEBUG_SERIALISATION_ROUNDTRIP:
            # this is a debug message. Deserialize the contents, print them to stdout, reserialize and send back
            try:
                print("Received data: ", message.data)
                print("---------------")

                aplarr = APLArray.fromJSONString(message.data)
                serialized = aplarr.toJSONString()

                print("Sending back: ", serialized)
                print("---------------")

                Message(MessageType.DEBUG_SERIALISATION_ROUNDTRIP, serialized).send(self.outfile)
            except Exception as e:
                Message(MessageType.ERR, repr(e)).send(self.outfile)          
        else:
            Message(MessageType.ERR, "unknown message type #%d / data:%s"%(message.type,message.data)).send(self.outfile)

