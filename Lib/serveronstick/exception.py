"""
common exceptions for the serveronstick package
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'SoS_Error',
    'SoS_WrongInputSize',
    'SoS_WrongInputType',
    'SoS_CommandFailed'
]

class SoS_Error(Exception):
    """
    Base class for SoS exceptions in this package.

    Attributes:
        reason -- explanation of the error
    """

    def __init__(self, reason):
        Exception.__init__(self)
        self.reason = reason

    def __str__(self):
        return '<%s instance at %s: %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.reason
            )

class SoS_WrongInputSize(SoS_Error):
    """
    Exception raised for errors in the size of an argument to some function.
    """
    def __init__(self, name, expected, size):
        reason = "Bad size of argument '%s', expected %i got %i" % (name, expected, size)
        SoS_Error.__init__(self, reason)

class SoS_WrongInputType(SoS_Error):
    """
    Exception raised for errors in the type of an argument to some function.
    """
    def __init__(self, name, expected, name_type):
        reason = "Bad type of argument '%s', expected %s got %s" % (name, expected, name_type)
        SoS_Error.__init__(self, reason)

class SoS_CommandFailed(SoS_Error):
    """
    Exception raised when a command sent to the SoS returned an error.
    """
    def __init__(self, name, status):
        reason = "Command %s failed: %i" % (name, status)
        SoS_Error.__init__(self, reason)
