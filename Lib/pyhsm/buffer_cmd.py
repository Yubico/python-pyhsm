"""
implementations of internal buffer commands for YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_Buffer_Load',
    'YHSM_Cmd_Buffer_Random_Load',
]

import pyhsm.defines
import pyhsm.exception
from pyhsm.cmd import YHSM_Cmd

class YHSM_Cmd_Buffer_Load(YHSM_Cmd):
    """
    Ask YubiHSM to load some data into it's internal buffer.

    @ivar data_len: Number of bytes (to be) loaded
    @ivar offset: Offset in internal buffer where data will be/was loaded

    @type data_len: integer
    @type offset: integer
    """

    data_len = 0
    offest = 0

    def __init__(self, stick, data, offset = 0):
        data = pyhsm.util.input_validate_str(data, 'data', max_len = pyhsm.defines.YSM_DATA_BUF_SIZE)
        self.data_len = len(data)
        self.offset = pyhsm.util.input_validate_int(offset, 'offset', pyhsm.defines.YSM_DATA_BUF_SIZE - 1)
        # typedef struct {
        #   uint8_t offs;                       // Offset in buffer. Zero flushes/resets buffer first
        #   uint8_t numBytes;                   // Number of bytes to load
        #   uint8_t data[YSM_DATA_BUF_SIZE];    // Data to load
        # } YSM_BUFFER_LOAD_REQ;
        fmt = "B B %is" % self.data_len
        packed = struct.pack(fmt, self.offset, self.data_len, data)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_BUFFER_LOAD, packed)

    def parse_result(self, data):
        """
        Parse result of L{pyhsm.defines.YSM_BUFFER_LOAD} command.

        @return: Number of bytes now in the YubiHSM internal buffer.
        @rtype: integer

        @raise pyhsm.exception.YHSM_Error: Unexpected number of bytes were loaded
        """
        # typedef struct {
        #   uint8_t numBytes;                   // Number of bytes in buffer now
        # } YSM_BUFFER_LOAD_RESP;
        count = ord(data[0])
        if self.offset == 0:
            # if offset was 0, the buffer was reset and
            # we can verify the length returned
            if count != self.data_len:
                raise pyhsm.exception.YHSM_Error("Incorrect number of bytes in buffer (got %i, expected %i)" \
                                               % (self.data_len, count))
        return count

class YHSM_Cmd_Buffer_Random_Load(YHSM_Cmd):
    """
    Ask YubiHSM to generate a secret for a specific public_id

    Generated secret is stored in YubiHSM's internal memory and is
    retreived using YHSM_Cmd_Blob_Generate.
    """
    def __init__(self, stick, num_bytes, offset = 0):
        self.offset = offset
        self.num_bytes = num_bytes
        # typedef struct {
        #   uint8_t offs;                       // Offset in buffer. Zero flushes/resets buffer first
        #   uint8_t numBytes;                   // Number of bytes to randomize
        # } YSM_BUFFER_RANDOM_LOAD_REQ;
        fmt = "B B"
        packed = struct.pack(fmt, self.offset, self.num_bytes)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_BUFFER_RANDOM_LOAD, packed)

    def parse_result(self, data):
        """ Return True if the public_id in the response matches the one in the request. """
        # typedef struct {
        #   uint8_t numBytes;                   // Number of bytes in buffer now
        # } YSM_BUFFER_LOAD_RESP;
        count = ord(data[0])
        if self.offset == 0:
            # if offset was 0, the buffer was reset and
            # we can verify the length returned
            if count != self.num_bytes:
                raise pyhsm.exception.YHSM_Error("Incorrect number of bytes in buffer (got %i, expected %i)" \
                                               % (self.num_bytes, count))
        return count
