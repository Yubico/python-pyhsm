"""
module for accessing a YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import re
import struct

__all__ = [
    # constants
    # functions
    'reset',
    # classes
    'YHSM_Cmd',
]

import pyhsm.exception
import pyhsm.defines

class YHSM_Cmd():
    """
    Base class for YubiHSM commands.
    """

    response_status = None
    executed = False

    def __init__(self, stick, command, payload=''):
        """
        The base class for all YSM_ commands.

        @param stick: Reference to a YubiHSM
        @param command: The YSM_xxx command defined in pyhsm.defines.
        @param payload: a packed C struct, represented as a Python string

        @type stick: L{pyhsm.stick.YHSM_Stick}
        @type command: integer
        @type payload: string
        """
        self.stick = stick
        self.command = command
        self.payload = payload
        return None

    def execute(self, read_response=True):
        """
        Write command to HSM and read response.

        @param read_response: Whether to expect a response or not.
        @type read_response: bool
        """
        # // Up- and downlink packet
        # typedef struct {
        #   uint8_t bcnt;                       // Number of bytes (cmd + payload)
        #   uint8_t cmd;                        // YSM_xxx command
        #   uint8_t payload[YSM_MAX_PKT_SIZE];  // Payload
        # } YSM_PKT;
        if self.command != pyhsm.defines.YSM_NULL:
            # YSM_NULL is the exception to the rule - it should NOT be prefixed with YSM_PKT.bcnt
            cmd_buf = struct.pack('BB', len(self.payload) + 1, self.command)
        else:
            cmd_buf = chr(self.command)
        cmd_buf += self.payload
        debug_info = None
        unlock = self.stick.acquire()
        try:
            if self.stick.debug:
                debug_info = "%s (payload %i/0x%x)" % (pyhsm.defines.cmd2str(self.command), \
                                                        len(self.payload), len(self.payload))
            self.stick.write(cmd_buf, debug_info)
            if not read_response:
                return None
            return self._read_response()
        finally:
            unlock()

    def _read_response(self):
        """
        After writing a command, read response.

        @returns: Result of parse_data()

        @raises pyhsm.exception.YHSM_Error: On failure to read a response to the
            command we sent in a timely fashion.
        """
        # // Up- and downlink packet
        # typedef struct {
        #   uint8_t bcnt;                       // Number of bytes (cmd + payload)
        #   uint8_t cmd;                        // YSM_xxx command
        #   uint8_t payload[YSM_MAX_PKT_SIZE];  // Payload
        # } YSM_PKT;

        # read YSM_PKT.bcnt and YSM_PKT.cmd
        res = self.stick.read(2, 'response length + response status')
        if len(res) != 2:
            self._handle_invalid_read_response(res, 2)
        response_len, response_status = struct.unpack('BB', res)
        response_len -= 1 # the status byte has been read already
        debug_info = None
        if response_status & pyhsm.defines.YSM_RESPONSE:
            debug_info = "%s response (%i/0x%x bytes)" \
                % (pyhsm.defines.cmd2str(response_status - pyhsm.defines.YSM_RESPONSE), \
                       response_len, response_len)
        # read YSM_PKT.payload
        res = self.stick.read(response_len, debug_info)
        if res:
            if response_status == self.command | pyhsm.defines.YSM_RESPONSE:
                self.executed = True
                self.response_status = response_status
                return self.parse_result(res)
            else:
                reset(self.stick)
                raise pyhsm.exception.YHSM_Error('YubiHSM responded to wrong command')
        else:
            raise pyhsm.exception.YHSM_Error('YubiHSM did not respond')

    def _handle_invalid_read_response(self, res, expected_len):
        """
        This function is called when we do not get the expected frame header in
        response to a command. Probable reason is that we are not talking to a
        YubiHSM in HSM mode (might be a modem, or a YubiHSM in configuration mode).

        Throws a hopefully helpful exception.
        """
        if not res:
            reset(self.stick)
            raise pyhsm.exception.YHSM_Error('YubiHSM did not respond to command %s' \
                                                 % (pyhsm.defines.cmd2str(self.command)) )
        # try to check if it is a YubiHSM in configuration mode
        self.stick.write('\r\r\r', '(mode test)')
        res2 = self.stick.read(50) # expect a timeout
        lines = res2.split('\n')
        for this in lines:
            if re.match('^(NO_CFG|WSAPI|HSM).*> .*', this):
                raise pyhsm.exception.YHSM_Error('YubiHSM is in configuration mode')
        raise pyhsm.exception.YHSM_Error('Unknown response from serial device %s : "%s"' \
                                             % (self.stick.device, res.encode('hex')))

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
    nulls = (pyhsm.defines.YSM_MAX_PKT_SIZE - 1) * '\x00'
    res = YHSM_Cmd(stick, pyhsm.defines.YSM_NULL, payload = nulls).execute(read_response = False)
    unlock = stick.acquire()
    try:
        stick.flush()
    finally:
        unlock()
    return res == 0
