"""
implementations of HMAC commands to execute on a YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_HMAC_SHA1_Write',
    'YHSM_GeneratedHMACSHA1',
]

import pyhsm.exception
import pyhsm.defines
from pyhsm.cmd import YHSM_Cmd

class YHSM_Cmd_HMAC_SHA1_Write(YHSM_Cmd):
    """
    Calculate HMAC SHA1 using a key_handle in the YubiHSM.

    Set final=False to not get a hash generated for the initial request.

    Set to_buffer=True to get the SHA1 stored into the internal buffer, for
    use in some other cryptographic operation.
    """

    status = None
    result = None

    def __init__(self, stick, key_handle, data, flags = None, final = True, to_buffer = False):
        data = pyhsm.util.input_validate_str(data, 'data', max_len = pyhsm.defines.YSM_MAX_PKT_SIZE - 6)
        self.key_handle = pyhsm.util.input_validate_key_handle(key_handle)

        if flags != None:
            flags = pyhsm.util.input_validate_int(flags, 'flags', max_value=0xff)
        else:
            flags = pyhsm.defines.YSM_HMAC_SHA1_RESET
            if final:
                flags |= pyhsm.defines.YSM_HMAC_SHA1_FINAL
            if to_buffer:
                flags |= pyhsm.defines.YSM_HMAC_SHA1_TO_BUFFER

        self.final = final
        self.flags = flags
        packed = _raw_pack(self.key_handle, self.flags, data)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_HMAC_SHA1_GENERATE, packed)

    def next(self, data, final = False, to_buffer = False):
        """
        Add more input to the HMAC SHA1.
        """
        if final:
            self.flags = pyhsm.defines.YSM_HMAC_SHA1_FINAL
        else:
            self.flags = 0x0
        if to_buffer:
            self.flags |= pyhsm.defines.YSM_HMAC_SHA1_TO_BUFFER
        self.payload = _raw_pack(self.key_handle, self.flags, data)
        self.final = final
        return self

    def get_hash(self):
        """
        Get the HMAC-SHA1 that has been calculated this far.
        """
        if not self.executed:
            raise pyhsm.exception.YHSM_Error("HMAC-SHA1 hash not available, before execute().")
        return self.result.hash_result

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: key_handle=0x%x, flags=0x%x, executed=%s>' % (
                self.__class__.__name__,
                hex(id(self)),
                self.key_handle,
                self.flags,
                self.executed,
                )

    def parse_result(self, data):
        # typedef struct {
        #   uint32_t keyHandle;                 // Key handle
        #   YHSM_STATUS status;                 // Status
        #   uint8_t numBytes;                   // Number of bytes in hash output
        #   uint8_t hash[YSM_SHA1_HASH_SIZE];       // Hash output (if applicable)
        # } YHSM_HMAC_SHA1_GENERATE_RESP;
        key_handle, \
             self.status, \
             num_bytes = struct.unpack_from('<IBB', data, 0)

        pyhsm.util.validate_cmd_response_hex('key_handle', key_handle, self.key_handle)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            # struct.hash is not always of size YSM_SHA1_HASH_SIZE,
            # it is really the size of numBytes
            if num_bytes:
                sha1 = data[6:6 + num_bytes]
            else:
                sha1 = '\x00' * pyhsm.defines.YSM_SHA1_HASH_SIZE
            self.result = YHSM_GeneratedHMACSHA1(key_handle, sha1, self.final)
            return self
        else:
            raise pyhsm.exception.YHSM_CommandFailed('YHSM_HMAC_SHA1_GENERATE', self.status)

def _raw_pack(key_handle, flags, data):
    """
    Common code for packing payload to YHSM_HMAC_SHA1_GENERATE command.
    """
    # #define YHSM_HMAC_RESET          0x01    // Flag to indicate reset at first packet
    # #define YHSM_HMAC_FINAL          0x02    // Flag to indicate that the hash shall be calculated
    # typedef struct {
    #   uint32_t keyHandle;                 // Key handle
    #   uint8_t flags;                      // Flags
    #   uint8_t numBytes;                   // Number of bytes in data packet
    #   uint8_t data[YHSM_MAX_PKT_SIZE - 6]; // Data to be written
    # } YHSM_HMAC_SHA1_GENERATE_REQ;
    return struct.pack('<IBB', key_handle, flags, len(data)) + data

class YHSM_GeneratedHMACSHA1():
    """ Small class to represent a YHSM_HMAC_SHA1_GENERATE_RESP. """
    def __init__(self, key_handle, sha1, final):
        self.key_handle = key_handle
        self.hash_result = sha1
        self.final = final

    def __repr__(self):
        return '<%s instance at %s: key_handle=0x%x, trunc(hash_result)=%s, final=%s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.key_handle,
            self.hash_result[:4].encode('hex'),
            self.final,
            )
