"""
module for accessing a Server on a Stick

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import basic_cmd
import secrets_cmd

__all__ = [
    # constants
    ## statuses
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
    ## commands
    'SOS_NULL',
    'SOS_ECHO',
    'SOS_SYSTEM_INFO_QUERY',
    'SOS_RANDOM_GENERATE',
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

SOS_NULL		= 0x00
SOS_ECHO		= 0x01
SOS_SYSTEM_INFO_QUERY	= 0x02
SOS_SECRETS_GENERATE	= 0x03
SOS_SECRETS_LOAD	= 0x04
SOS_BLOB_GENERATE	= 0x05

SOS_RANDOM_GENERATE	= 0x0b

class SoS_Cmd():
    """
    Base class for Server-on-Stick commands.
    """
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
        """ Update payload after instantiation. """
        self.payload = data

    def parse_result(self, data):
        """
        This function is intended to be overridden by sub-classes that
        implements commands that should not just return the data read from
        the SoS.
        """
        return data

def reset(stick):
    """ Stream resynchronization. """
    stick.flushInput()
    nulls = (SOS_MAX_PKT_SIZE - 1) * '\x00'
    return SoS_Cmd(stick, SOS_NULL, payload = nulls).execute() == 0

def echo(stick, data):
    """ Send something to the stick, and expect to get it echoed back. """
    return basic_cmd.SoS_Cmd_Echo(stick, data).execute()

def system_info(stick):
    """ Get an object containing system information. """
    return basic_cmd.SoS_Cmd_System_Info(stick).execute()

def random(stick, bytes):
    """ Ask stick to generate a number of random bytes. """
    return basic_cmd.SoS_Cmd_Random(stick, bytes).execute()

def generate_secret(stick, publicId):
    """ Ask stick to generate a secret for a publicId. """
    return secrets_cmd.SoS_Cmd_Secrets_Generate(stick, publicId).execute()

def load_secret(stick, publicId, secrets):
    """ Ask stick to load an existing secret for a publicId. """
    return secrets_cmd.SoS_Cmd_Secrets_Load(stick, publicId, secrets).execute()

def generate_blob(stick, keyHandle):
    """
    Ask stick to encrypt the previously generated secret with a specific key,
    and return the resulting blob.
    """
    return secrets_cmd.SoS_Cmd_Blob_Generate(stick, keyHandle).execute()
