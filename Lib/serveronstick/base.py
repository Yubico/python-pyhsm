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
import defines

import basic_cmd
import secrets_cmd
import validate_cmd

class SoS():
    """
    Base class for accessing Server on Stick
    """

    def __init__(self, device, debug=False, timeout=1):
        self.debug = debug
        self.stick = stick.SoS_Stick(device, debug = self.debug, timeout = timeout)
        #cmd.reset(self.stick)
        self.reset()
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
        # Now verify we are in sync
        data = 'ekoeko'
        return self.echo(data) == data

    #
    # Basic commands
    #
    def echo(self, data):
        """ Echo test. """
        if type(data) is not str:
            raise exception.SoS_WrongInputType(
                'data', type(''), type(data))
        return basic_cmd.SoS_Cmd_Echo(self.stick, data).execute()

    def info(self):
        """ Get firmware version and unique ID from SoS. """
        return basic_cmd.SoS_Cmd_System_Info(self.stick).execute()

    def random(self, num_bytes):
        """ Get random bytes from SoS. """
        if type(num_bytes) is not int:
            raise exception.SoS_WrongInputType(
                'num_bytes', type(1), type(num_bytes))

        if type(bytes) is not int:
            assert()
        return basic_cmd.SoS_Cmd_Random(self.stick, bytes).execute()

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
            raise exception.SoS_WrongInputType(
                'publicId', type(''), type(publicId))
        return secrets_cmd.SoS_Cmd_Secrets_Generate(self.stick, publicId).execute()

    def load_secret(self, publicId, secrets):
        """
        Ask stick to load a pre-existing secret for a specific publicId.
        
        This is for importing keys into the HSM system.
        """
        if type(publicId) is not str:
            raise exception.SoS_WrongInputType(
                'publicId', type(''), type(publicId))
        return secrets_cmd.SoS_Cmd_Secrets_Load(self.stick, publicId, secrets).execute()

    def generate_blob(self, keyHandle):
        """
        Ask SoS to return the previously generated secret
        (see generate_secret()) encrypted with the specified keyHandle.
        """
        if type(keyHandle) is not int:
            assert()
        return secrets_cmd.SoS_Cmd_Blob_Generate(self.stick, keyHandle).execute()

    def validate_blob_otp(self, publicId, otp, keyHandle, blob):
        """
        Ask SoS to validate an OTP using a blob and a keyHandle to
        decrypt the blob.
        """
        if type(publicId) is not str:
            assert()
        if type(otp) is not str:
            assert()
        if type(keyHandle) is not int:
            assert()
        if type(blob) is not str:
            assert()
        return validate_cmd.SoS_Cmd_Blob_Validate_OTP( \
            self.stick, publicId, otp, keyHandle, blob).execute()
