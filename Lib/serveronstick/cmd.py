"""
module for accessing a Server on a Stick

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct

__all__ = [
    # constants
    'SOS_STATUS_OK',
    'SOS_KEY_HANDLE_INVALID',
    'SOS_BLOB_INVALID',
    'SOS_OTP_INVALID',
    'SOS_OTP_REPLAY',
    'SOS_ID_DUPLICATE',
    'SOS_ID_NOT_FOUND',
    'SOS_DB_FULL',
    'SOS_MEMORY_ERROR',
    'SOS_MEMORY_ERROR',
    'SOS_FUNCTION_DISABLED',
    # functions
    # classes
]

SOS_RESPONSE		= 0x80    # Response bit
SOS_MAX_PKT_SIZE	= 0x60    # Max size of a packet (excluding command byte)

SOS_STATUS_OK           = 0x80    # Executed successfully
SOS_KEY_HANDLE_INVALID  = 0x81    # Key handle is invalid
SOS_BLOB_INVALID        = 0x82    # Supplied blob is invalid
SOS_OTP_INVALID         = 0x83    # Supplied OTP is invalid (CRC or UID)
SOS_OTP_REPLAY          = 0x84    # Supplied OTP is replayed
SOS_ID_DUPLICATE        = 0x85    # The supplied public ID is already in the database
SOS_ID_NOT_FOUND        = 0x86    # The supplied public ID was not found in the database
SOS_DB_FULL             = 0x87    # The database storage is full
SOS_MEMORY_ERROR        = 0x88    # Memory read/write error
SOS_FUNCTION_DISABLED   = 0x89    # Funciton disabled via attribute(s)

SOS_NULL		= 0x0
SOS_ECHO		= 0x01
SOS_SYSTEM_INFO_QUERY	= 0x02
SOS_RANDOM_GENERATE	= 0x0b

class SoS_Cmd():

    def __init__(self, stick, command, payload=''):
        self.stick = stick
        self.command = command
        self.response_length = 0
        self.payload = payload
        self.executed = False
        return None

    def execute(self):
        """ Write command to stick and read response. """
        self.stick.write(chr(self.command) + self.payload)
        res = self.stick.read(self.response_length)
        if res:
            if ord(res[0]) == self.command | SOS_RESPONSE:
                self.executed = True
                return self.parse_result(res)
            else:
                reset(self.stick)
                raise Exception('Server-on-stick responded to wrong command')
        return ''

    def set_payload(self, data):
        self.payload = data

    def parse_result(self, data):
        return data


class SoS_Cmd_Echo(SoS_Cmd):
    """
    Send something to the stick, and expect to get it echoed back.
    """
    def __init__(self, stick, payload=''):
        packed = chr(len(payload)) + payload
        SoS_Cmd.__init__(self, stick, SOS_ECHO, packed)
        self.response_length = len(payload) + 2

    def parse_result(self, data):
        return data[2:]

    pass

class SoS_Cmd_System_Info(SoS_Cmd):
    """
    Request system information from the stick.
    """
    def __init__(self, stick):
        SoS_Cmd.__init__(self, stick, SOS_SYSTEM_INFO_QUERY)
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
        SoS_Cmd.__init__(self, stick, SOS_RANDOM_GENERATE, packed)
        self.response_length = bytes + 2

    pass

def reset(stick):
    """ Stream resynchronization. """
    stick.flushInput()
    nulls = (SOS_MAX_PKT_SIZE - 1) * '\x00'
    return SoS_Cmd(stick, SOS_NULL, payload = nulls).execute() == 0

def echo(stick, data):
    """ Send something to the stick, and expect to get it echoed back. """
    return SoS_Cmd_Echo(stick, data).execute()

def system_info(stick):
    """ Get an object containing system information. """
    return SoS_Cmd_System_Info(stick).execute()

def random(stick, bytes):
    """ Ask stick to generate a number of random bytes. """
    return SoS_Cmd_Random(stick, bytes).execute()
