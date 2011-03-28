"""
implementations of basic commands to execute on a YubiHSM

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_Echo',
    'YHSM_Cmd_System_Info',
    'YHSM_Cmd_Random',
]

from cmd import YHSM_Cmd

class YHSM_Cmd_Echo(YHSM_Cmd):
    """
    Send something to the stick, and expect to get it echoed back.
    """
    def __init__(self, stick, payload=''):
        if len(payload) > defines.YHSM_MAX_PKT_SIZE - 1:
            raise exception.YHSM_InputTooLong(
                'payload', defines.YHSM_MAX_PKT_SIZE - 1, len(data))
        packed = chr(len(payload)) + payload
        YHSM_Cmd.__init__(self, stick, defines.YHSM_ECHO, packed)

    def parse_result(self, data):
        # typedef struct {
        # uint8_t numBytes;                   // Number of bytes in data field
        # uint8_t data[YSM_MAX_PKT_SIZE - 1]; // Data
        # } YSM_ECHO_RESP;
        return data[1:]


class YHSM_Cmd_System_Info(YHSM_Cmd):
    """
    Request system information from the stick.
    """
    def __init__(self, stick):
        YHSM_Cmd.__init__(self, stick, defines.YHSM_SYSTEM_INFO_QUERY)
        self.version_major = 0
        self.version_minor = 0
        self.version_build = 0
        self.protocolVersion = 0
        self.systemUid = None

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
        # } YHSM_SYSTEM_INFO_RESP;
        self.version_major, \
            self.version_minor, \
            self.version_build, \
            self.protocolVersion, \
            self.systemUid = struct.unpack('BBBB12s', data)
        return self


class YHSM_Cmd_Random(YHSM_Cmd):
    """
    Ask stick to generate a number of random bytes.
    """
    def __init__(self, stick, num_bytes):
        packed = chr(num_bytes)
        YHSM_Cmd.__init__(self, stick, defines.YHSM_RANDOM_GENERATE, packed)

    def parse_result(self, data):
        # typedef struct {
        #   uint8_t numBytes;                   // Number of bytes generated
        #   uint8_t rnd[YSM_MAX_PKT_SIZE - 1];  // Random data
        # } YHSM_RANDOM_GENERATE_RESP;
        num_bytes = ord(data[0])
        return data[1:num_bytes]
