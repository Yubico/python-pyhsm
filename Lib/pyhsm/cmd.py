"""
module for accessing a YubiHSM
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.
import struct

import exception
import defines

__all__ = [
    # constants
    # functions
    'reset',
    # classes
    'YHSM_Cmd',
]

class YHSM_Cmd():
    """
    Base class for YubiHSM commands.
    """
    def __init__(self, stick, command, payload=''):
        self.stick = stick
        self.command = command
        self.response_length = 0
        self.payload = payload
        self.executed = False
        return None

    def execute(self, read_response=True):
        """ Write command to stick and read response. """
        # // Up- and downlink packet
        # typedef struct {
        #   uint8_t bcnt;                       // Number of bytes (cmd + payload)
        #   uint8_t cmd;                        // YSM_xxx command
        #   uint8_t payload[YSM_MAX_PKT_SIZE];  // Payload
        # } YSM_PKT;
        if self.command != defines.YHSM_NULL:
            cmd_buf = struct.pack('BB', len(self.payload) + 1, self.command)
        else:
            cmd_buf = chr(self.command)
        cmd_buf += self.payload
        debug_info = None
        if self.stick.debug:
            debug_info = "%s (payload %i)" % (defines.cmd2str(self.command), \
                                                  len(self.payload))
        self.stick.write(cmd_buf, debug_info)
        if not read_response:
            return None
        # read response status
        res = self.stick.read(2, 'response length + status')
        if not res:
            if self.response_length > 0:
                reset(self.stick)
                raise exception.YHSM_Error('YubiHSM did not respond')
            return None
        response_len, response_status = struct.unpack('BB', res)
        response_len -= 1 # the status byte has been read already
        debug_info = None
        if response_status & defines.YHSM_RESPONSE:
            debug_info = "%s response (%i bytes)" \
                % (defines.cmd2str(response_status - defines.YHSM_RESPONSE), \
                       response_len)
        # read response payload
        res = self.stick.read(response_len, debug_info)
        if res:
            if response_status == self.command | defines.YHSM_RESPONSE:
                self.executed = True
                self.response_status = response_status
                return self.parse_result(res)
            else:
                reset(self.stick)
                raise exception.YHSM_Error('YubiHSM responded to wrong command')
        else:
            raise exception.YHSM_Error('YubiHSM did not respond')

    def parse_result(self, data):
        """
        This function is intended to be overridden by sub-classes that
        implements commands that should not just return the data read from
        the YubiHSM.
        """
        return data

def reset(stick):
    """
    Send a bunch of zero-bytes to the YubiHSM, and flush the input buffer.
    """
    nulls = (defines.YHSM_MAX_PKT_SIZE - 1) * '\x00'
    res = YHSM_Cmd(stick, defines.YHSM_NULL, payload = nulls).execute(read_response = False)
    stick.flush()
    return res == 0
