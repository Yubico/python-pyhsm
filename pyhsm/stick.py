"""
module for actually talking to the YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    # functions
    'read',
    'write',
    'flush',
    # classes
    'YHSM_Stick',
]

import sys
import serial

import pyhsm.util
import pyhsm.exception

class YHSM_Stick():
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
        self.num_read_bytes = 0
        self.num_write_bytes = 0
        self.ser = None # to not bomb in destructor on open fail
        self.ser = serial.serial_for_url(device)
        self.ser.baudrate = 115200
        self.ser.timeout = timeout
        if self.debug:
            sys.stderr.write("%s: OPEN %s\n" %(
                    self.__class__.__name__,
                    self.ser
                    ))
        return None

    def acquire(self):
        """
        Do nothing
        """
        return self.acquire

    def write(self, data, debug_info=None):
        """
        Write data to YHSM device.
        """
        self.num_write_bytes += len(data)
        if self.debug:
            if not debug_info:
                debug_info = str(len(data))
            sys.stderr.write("%s: WRITE %s:\n%s\n" %(
                    self.__class__.__name__,
                    debug_info,
                    pyhsm.util.hexdump(data)
                    ))
        return self.ser.write(data)

    def read(self, num_bytes, debug_info=None):
        """
        Read a number of bytes from YubiHSM device.
        """
        if self.debug:
            if not debug_info:
                debug_info = str(num_bytes)
            sys.stderr.write("%s: READING %s\n" %(
                    self.__class__.__name__,
                    debug_info
                    ))
        res = self.ser.read(num_bytes)
        if self.debug:
            sys.stderr.write("%s: READ %i:\n%s\n" %(
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
        if self.debug:
            sys.stderr.write("%s: FLUSH INPUT (%i bytes waiting)\n" %(
                    self.__class__.__name__,
                    self.ser.inWaiting()
                    ))
        self.ser.flushInput()

    def drain(self):
        """ Drain input. """
        if self.debug:
            sys.stderr.write("%s: DRAIN INPUT (%i bytes waiting)\n" %(
                    self.__class__.__name__,
                    self.ser.inWaiting()
                    ))
        old_timeout = self.ser.timeout
        self.ser.timeout = 0.1
        data = self.ser.read(1)
        while len(data):
            if self.debug:
                sys.stderr.write("%s: DRAINED 0x%x (%c)\n" %(self.__class__.__name__, ord(data[0]), data[0]))
            data = self.ser.read(1)
        self.ser.timeout = old_timeout
        return True

    def raw_device(self):
        """ Get raw serial device. Only intended for test code/debugging! """
        return self.ser

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
            sys.stderr.write("%s: CLOSE %s\n" %(
                    self.__class__.__name__,
                    self.ser
                    ))
        if self.ser:
            self.ser.close()
