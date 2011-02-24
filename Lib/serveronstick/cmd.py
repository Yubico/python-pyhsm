"""
module for accessing a Server on a Stick

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import exception
import defines

__all__ = [
    # constants
    # functions
    # classes
]

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
            if ord(res[0]) == self.command | defines.SOS_RESPONSE:
                self.executed = True
                return self.parse_result(res)
            else:
                reset(self.stick)
                raise exception.SoS_Error('Server-on-stick responded to wrong command')
        elif self.response_length > 0:
            reset(self.stick)
            raise exception.SoS_Error('Server-on-stick did not respond')
        return ''

    def parse_result(self, data):
        """
        This function is intended to be overridden by sub-classes that
        implements commands that should not just return the data read from
        the SoS.
        """
        return data

def reset(stick):
    """
    Send a bunch of zero-bytes to the SoS, and flush the input buffer.
    """
    nulls = (defines.SOS_MAX_PKT_SIZE - 1) * '\x00'
    res = SoS_Cmd(stick, defines.SOS_NULL, payload = nulls).execute()
    stick.flush()
    return res == 0
