"""
implementations of internal buffer commands for YubiHSM
"""

# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_Buffer_Load',
]

from cmd import YHSM_Cmd
import exception

class YHSM_Cmd_Buffer_Load(YHSM_Cmd):
    """
    Ask YubiHSM to load some data into it's internal buffer.
    """
    def __init__(self, stick, data, offset = 0):
        if len(data) > defines.YHSM_DATA_BUF_SIZE:
            raise exception.YHSM_InputTooLong(
                'data', defines.YHSM_DATA_BUF_SIZE, len(data))
        # typedef struct {
        #   uint8_t offs;                       // Offset in buffer. Zero flushes/resets buffer first
        #   uint8_t numBytes;                   // Number of bytes to load
        #   uint8_t data[YSM_DATA_BUF_SIZE];    // Data to load
        # } YSM_BUFFER_LOAD_REQ;
        packed = struct.pack("B B %is" % len(data), \
                             offset, len(data), data)
        YHSM_Cmd.__init__(self, stick, defines.YHSM_BUFFER_LOAD, packed)

    def parse_result(self, data):
        """ Return True if the public_id in the response matches the one in the request. """
        # typedef struct {
        #   uint8_t numBytes;                   // Number of bytes in buffert now
        # } YSM_BUFFER_LOAD_RESP;
        return data[0]
