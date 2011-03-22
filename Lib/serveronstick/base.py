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
import exception

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

        return basic_cmd.SoS_Cmd_Random(self.stick, num_bytes).execute()

    #
    # Secrets/blob commands
    #
    def generate_secret(self, public_id):
        """
        Ask SoS to generate a secret for a public_id.

        The result is stored internally in the SoS in temporary memory -
        this operation would be followed by one or more generate_blob()
        commands to actually retreive the generated secret (in encrypted form).
        """
        if type(public_id) is not str:
            raise exception.SoS_WrongInputType(
                'public_id', type(''), type(public_id))
        return secrets_cmd.SoS_Cmd_Secrets_Generate(self.stick, public_id).execute()

    def load_secret(self, public_id, secrets):
        """
        Ask stick to load a pre-existing secret for a specific public_id.
        
        This is for importing keys into the HSM system.
        """
        if type(public_id) is not str:
            raise exception.SoS_WrongInputType(
                'public_id', type(''), type(public_id))
        return secrets_cmd.SoS_Cmd_Secrets_Load(self.stick, public_id, secrets).execute()

    def generate_blob(self, key_handle):
        """
        Ask SoS to return the previously generated secret
        (see generate_secret()) encrypted with the specified key_handle.
        """
        if type(key_handle) is not int:
            assert()
        return secrets_cmd.SoS_Cmd_Blob_Generate(self.stick, key_handle).execute()

    def validate_blob_otp(self, public_id, otp, key_handle, blob):
        """
        Ask SoS to validate an OTP using a blob and a key_handle to
        decrypt the blob.
        """
        if type(public_id) is not str:
            assert()
        if type(otp) is not str:
            assert()
        if type(key_handle) is not int:
            assert()
        if type(blob) is not str:
            assert()
        return validate_cmd.SoS_Cmd_Blob_Validate_OTP( \
            self.stick, public_id, otp, key_handle, blob).execute()
