# Copyright (c) 2011, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'Stick'
]

import serial
import sys
import util

class SoS_Stick():
    def __init__(self, device, timeout=1, debug=False):
        self.debug = debug
        self.device = device
        self.num_read_bytes = 0
        self.num_write_bytes = 0
        self.ser = serial.Serial(device, 115200, timeout = timeout)
        if self.debug:
            sys.stderr.write("%s: OPEN %s\n" %(
                    self.__class__.__name__,
                    self.ser
                    ))
        return None

    def write(self, data):
        self.num_write_bytes += len(data)
        if self.debug:
            sys.stderr.write("%s: WRITE %i:\n%s\n" %(
                    self.__class__.__name__,
                    len(data),
                    util.hexdump(data)
                    ))
        return self.ser.write(data)

    def read(self, bytes):
        if bytes < 1:
            return 0
        if self.debug:
            sys.stderr.write("%s: READING %i\n" %(
                    self.__class__.__name__,
                    bytes
                    ))
        res = self.ser.read(bytes)
        if self.debug:
            sys.stderr.write("%s: READ %i:\n%s\n" %(
                    self.__class__.__name__,
                    len(res),
                    util.hexdump(res)
                    ))
        self.num_read_bytes += len(res)
        return res

    def flushInput(self):
        self.ser.flushInput()

    def __repr__(self):
        return '<%s instance at %s: %s - r:%i w:%i>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.device,
            self.num_read_bytes,
            self.num_write_bytes
            )

    def __del__(self):
        if self.debug:
            sys.stderr.write("%s: CLOSE %s\n" %(
                    self.__class__.__name__,
                    self.ser
                    ))
        self.ser.close()
