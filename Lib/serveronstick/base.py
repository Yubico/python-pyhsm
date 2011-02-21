"""
module for accessing a Server on a Stick

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'SoS'
]

_PUBLIC_ID_SIZE = 6	# Size of public id for std OTP validation
_OTP_SIZE	= 16	# Size of OTP
_SOS_BLOCK_SIZE	= 16	# Size of block operations
_BLOB_KEY_SIZE	= 32	# Size of blob key

#from serveronstick  import __version__
import cmd
import stick
import util

class SoS():
    """
    Base class for accessing Server on Stick
    """

    def __init__(self, device, debug=False):
        self.debug = debug
        self.stick = stick.SoS_Stick(device, debug = self.debug)
        return None

    def __repr__(self):
        return '<%s instance at %s: %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.stick.device
            )

    def reset(self):
        """ Perform stream resynchronization. Return True if successful. """
        cmd.reset(self.stick)
        echo = 'ekoeko'
        return cmd.echo(self.stick, echo) == echo

    def echo(self, data):
        """ Echo test. """
        return cmd.echo(self.stick, data)

    def info(self):
        """ Get firmware version and unique ID from SoS. """
        return cmd.system_info(self.stick)

    def random(self, bytes):
        """ Get random bytes from SoS. """
        return cmd.random(self.stick, bytes)
