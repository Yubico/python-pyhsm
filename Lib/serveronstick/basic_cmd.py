"""
implementations of basic commands to execute on a Server on Stick

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct

__all__ = [
    # constants
    # functions
    # classes
    'SoS_Cmd_Echo',
    'SoS_Cmd_System_Info',
    'SoS_Cmd_Random',
]

import cmd
from cmd import SoS_Cmd

class SoS_Cmd_Echo(SoS_Cmd):
    """
    Send something to the stick, and expect to get it echoed back.
    """
    def __init__(self, stick, payload=''):
        packed = chr(len(payload)) + payload
        SoS_Cmd.__init__(self, stick, cmd.SOS_ECHO, packed)
        self.response_length = len(payload) + 2

    def parse_result(self, data):
        return data[2:]

    pass

class SoS_Cmd_System_Info(SoS_Cmd):
    """
    Request system information from the stick.
    """
    def __init__(self, stick):
        SoS_Cmd.__init__(self, stick, cmd.SOS_SYSTEM_INFO_QUERY)
        self.response_length = 17
        self.versionMajor = '?'

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: ver=%s, proto=%s, sysid=%s>' % (
                self.__class__.__name__,
                hex(id(self)),
                (self.versionMajor, self.versionMinor, self.versionBuild),
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
        #   uint8_t versionMajor;               // Major version #
        #   uint8_t versionMinor;               // Minor version #
        #   uint8_t versionBuild;               // Build version #
        #   uint8_t protocolVersion;            // Protocol version #
        #   uint8_t systemUid[SYSTEM_ID_SIZE];  // System unique identifier
        # } SOS_SYSTEM_INFO_RESP;
        self.versionMajor, \
            self.versionMinor, \
            self.versionBuild, \
            self.protocolVersion, \
            self.systemUid = struct.unpack('xBBBB12s', data)
        return self

    pass

class SoS_Cmd_Random(SoS_Cmd):
    """
    Ask stick to generate a number of random bytes.
    """
    def __init__(self, stick, bytes):
        packed = chr(bytes)
        SoS_Cmd.__init__(self, stick, cmd.SOS_RANDOM_GENERATE, packed)
        self.response_length = bytes + 2

    pass

