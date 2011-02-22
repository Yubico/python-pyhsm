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

    #
    # Basic commands
    #
    def echo(self, data):
        """ Echo test. """
        if type(data) is not str:
            assert()
        return cmd.echo(self.stick, data)

    def info(self):
        """ Get firmware version and unique ID from SoS. """
        return cmd.system_info(self.stick)

    def random(self, bytes):
        """ Get random bytes from SoS. """
        if type(bytes) is not int:
            assert()
        return cmd.random(self.stick, bytes)

    #
    # Secrets/blob commands
    #
    def generate_secret(self, publicId):
        """
        Ask SoS to generate a secret for a publicId.

        The result is stored internally in the SoS in temporary memory -
        this operation would be followed by one or more generate_blob()
        commands to actually retreive the generated secret (in encrypted form).
        """
        if type(publicId) is not str:
            assert()
        return cmd.generate_secret(self.stick, publicId)

    def load_secret(self, publicId, secrets):
        """
        Ask stick to load a pre-existing secret for a specific publicId.
        
        This is for importing keys into the HSM system.
        """
        if type(publicId) is not str:
            assert()
        if type(secrets) is not str:
            assert()
        return cmd.load_secret(self.stick, publicId, secrets)

    def generate_blob(self, keyHandle):
        """
        Ask SoS to return the previously generated secret
        (see generate_secret()) encrypted with the specified keyHandle.
        """
        if type(keyHandle) is not int:
            assert()
        return cmd.generate_blob(self.stick, keyHandle)
