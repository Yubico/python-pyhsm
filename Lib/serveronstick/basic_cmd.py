"""
implementations of basic commands to execute on a Server on Stick

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'SoS_Cmd_Echo',
    'SoS_Cmd_System_Info',
    'SoS_Cmd_Random',
]

from cmd import SoS_Cmd

class SoS_Cmd_Echo(SoS_Cmd):
    """
    Send something to the stick, and expect to get it echoed back.
    """
    def __init__(self, stick, payload=''):
        packed = chr(len(payload)) + payload
        SoS_Cmd.__init__(self, stick, defines.SOS_ECHO, packed)
        self.response_length = len(payload) + 2

    def parse_result(self, data):
        return data[2:]


class SoS_Cmd_System_Info(SoS_Cmd):
    """
    Request system information from the stick.
    """
    def __init__(self, stick):
        SoS_Cmd.__init__(self, stick, defines.SOS_SYSTEM_INFO_QUERY)
        self.version_major = 0
        self.version_minor = 0
        self.version_build = 0
        self.protocolVersion = 0
        self.systemUid = None
        self.response_length = 17

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: ver=%s, proto=%s, sysid=0x%s>' % (
                self.__class__.__name__,
                hex(id(self)),
                (self.version_major, self.version_minor, self.version_build),
                self.protocolVersion,
                self.systemUid.encode('hex')
                )
        else:
            return '<%s instance at %s (not executed)>' % (
                self.__class__.__name__,
                hex(id(self))
                )

    def parse_result(self, data):
        # #define SYSTEM_ID_SIZE          12
        # typedef struct {
        #   uint8_t version_major;               // Major version #
        #   uint8_t version_minor;               // Minor version #
        #   uint8_t version_build;               // Build version #
        #   uint8_t protocolVersion;            // Protocol version #
        #   uint8_t systemUid[SYSTEM_ID_SIZE];  // System unique identifier
        # } SOS_SYSTEM_INFO_RESP;
        self.version_major, \
            self.version_minor, \
            self.version_build, \
            self.protocolVersion, \
            self.systemUid = struct.unpack('xBBBB12s', data)
        return self


class SoS_Cmd_Random(SoS_Cmd):
    """
    Ask stick to generate a number of random bytes.
    """
    def __init__(self, stick, num_bytes):
        packed = chr(num_bytes)
        SoS_Cmd.__init__(self, stick, defines.SOS_RANDOM_GENERATE, packed)
        self.response_length = num_bytes + 2

