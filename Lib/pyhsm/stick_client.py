"""
module for talking to the YubiHSM over a socket.
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Stick_Client',
]

import sys
import re
import socket
import pickle

import pyhsm.util
import pyhsm.exception


CMD_WRITE = 0
CMD_READ = 1
CMD_FLUSH = 2
CMD_DRAIN = 3
CMD_LOCK = 4
CMD_UNLOCK = 5


DEVICE_PATTERN = re.compile(r'daemon://(?P<host>[^:]+)(:(?P<port>\d+))?')


class YHSM_Stick_Client():
    """
    The current YHSM is a USB device using serial communication.

    This class exposes the basic functions read, write and flush (input).
    """
    def __init__(self, device, timeout=1, debug=False):
        """
        Open YHSM device.
        """
        self.debug = debug
        self.device = device
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        match = DEVICE_PATTERN.match(device)
        self.socket.connect((match.group('host'), int(match.group('port'))))
        self.socket_file = self.socket.makefile('wb')

        self.num_read_bytes = 0
        self.num_write_bytes = 0
        if self.debug:
            sys.stderr.write("%s: OPEN %s\n" % (
                self.__class__.__name__,
                self.socket
            ))
        return None

    def acquire(self):
        pickle.dump((CMD_LOCK,), self.socket_file)
        self.socket_file.flush()
        return self.release

    def release(self):
        pickle.dump((CMD_UNLOCK,), self.socket_file)
        self.socket_file.flush()

    def write(self, data, debug_info=None):
        """
        Write data to YHSM device.
        """
        self.num_write_bytes += len(data)
        if self.debug:
            if not debug_info:
                debug_info = str(len(data))
            sys.stderr.write("%s: WRITE %s:\n%s\n" % (
                self.__class__.__name__,
                debug_info,
                pyhsm.util.hexdump(data)
            ))
        pickle.dump((CMD_WRITE, data), self.socket_file)
        self.socket_file.flush()
        return pickle.load(self.socket_file)

    def read(self, num_bytes, debug_info=None):
        """
        Read a number of bytes from YubiHSM device.
        """
        if self.debug:
            if not debug_info:
                debug_info = str(num_bytes)
            sys.stderr.write("%s: READING %s\n" % (
                self.__class__.__name__,
                debug_info
            ))
        pickle.dump((CMD_READ, num_bytes), self.socket_file)
        self.socket_file.flush()
        res = pickle.load(self.socket_file)

        if self.debug:
            sys.stderr.write("%s: READ %i:\n%s\n" % (
                self.__class__.__name__,
                len(res),
                pyhsm.util.hexdump(res)
            ))
        self.num_read_bytes += len(res)
        return res

    def flush(self):
        """
        Flush input buffers.
        """
        pickle.dump((CMD_FLUSH,), self.socket_file)
        self.socket_file.flush()
        return pickle.load(self.socket_file)

    def drain(self):
        """ Drain input. """
        pickle.dump((CMD_DRAIN,), self.socket_file)
        self.socket_file.flush()
        return pickle.load(self.socket_file)

    def raw_device(self):
        """ Get the socket address. Only intended for test code/debugging! """
        return self.device

    def set_debug(self, new):
        """
        Set debug mode (boolean).

        Returns old setting.
        """
        if type(new) is not bool:
            raise pyhsm.exception.YHSM_WrongInputType(
                'new', bool, type(new))
        old = self.debug
        self.debug = new
        return old

    def __repr__(self):
        return '<%s instance at %s: %s - r:%i w:%i>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.device,
            self.num_read_bytes,
            self.num_write_bytes
        )

    def __del__(self):
        """
        Close device when YHSM instance is destroyed.
        """
        if self.debug:
            sys.stderr.write("%s: CLOSE %s\n" % (
                self.__class__.__name__,
                self.device
            ))
        try:
            self.socket_file.close()
            self.socket.close()
        except Exception:
            pass
