"""
common exceptions for the pyhsm package
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Error',
    'YHSM_InputTooShort',
    'YHSM_InputTooLong',
    'YHSM_WrongInputSize',
    'YHSM_WrongInputType',
    'YHSM_CommandFailed'
]

import pyhsm.defines

class YHSM_Error(Exception):
    """
    Base class for YHSM exceptions in this package.

    @ivar reason: explanation of the error
    @type reason: string
    """

    reason = None

    def __init__(self, reason):
        Exception.__init__(self)
        self.reason = reason

    def __str__(self):
        return '<%s instance at %s: %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.reason
            )

class YHSM_WrongInputSize(YHSM_Error):
    """
    Exception raised for errors in the size of an argument to some function.
    """
    def __init__(self, name, expected, size):
        reason = "Bad size of argument '%s', expected %i got %i" % (name, expected, size)
        YHSM_Error.__init__(self, reason)

class YHSM_InputTooShort(YHSM_Error):
    """
    Exception raised for too short input to some function.
    """
    def __init__(self, name, expected, size):
        reason = "Argument '%s' too short, expected min %i got %i" % (name, expected, size)
        YHSM_Error.__init__(self, reason)

class YHSM_InputTooLong(YHSM_Error):
    """
    Exception raised for too long input to some function.
    """
    def __init__(self, name, expected, size):
        reason = "Argument '%s' too long, expected max %i got %i" % (name, expected, size)
        YHSM_Error.__init__(self, reason)

class YHSM_WrongInputType(YHSM_Error):
    """
    Exception raised for errors in the type of an argument to some function.
    """
    def __init__(self, name, expected, name_type):
        reason = "Bad type of argument '%s', expected %s got %s" % (name, expected, name_type)
        YHSM_Error.__init__(self, reason)

class YHSM_CommandFailed(YHSM_Error):
    """
    Exception raised when a command sent to the YubiHSM returned an error.
    """
    def __init__(self, name, status):
        self.status = status
        self.status_str = pyhsm.defines.status2str(status)
        reason = "Command %s failed: %s" % (name, self.status_str)
        YHSM_Error.__init__(self, reason)
