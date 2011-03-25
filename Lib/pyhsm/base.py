"""
module for accessing a YubiHSM

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'YHSM'
]

#from pyhsm  import __version__
import cmd
import stick
import util
import defines
import exception

import basic_cmd
import debug_cmd
import secrets_cmd
import validate_cmd

class YHSM():
    """
    Base class for accessing YubiHSM
    """

    def __init__(self, device, debug=False, timeout=1):
        self.debug = debug
        self.stick = stick.YHSM_Stick(device, debug = self.debug, timeout = timeout)
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
            raise exception.YHSM_WrongInputType(
                'data', type(''), type(data))
        return basic_cmd.YHSM_Cmd_Echo(self.stick, data).execute()

    def info(self):
        """ Get firmware version and unique ID from YubiHSM. """
        return basic_cmd.YHSM_Cmd_System_Info(self.stick).execute()

    def random(self, num_bytes):
        """ Get random bytes from YubiHSM. """
        if type(num_bytes) is not int:
            raise exception.YHSM_WrongInputType(
                'num_bytes', type(1), type(num_bytes))

        return basic_cmd.YHSM_Cmd_Random(self.stick, num_bytes).execute()

    #
    # Secrets/blob commands
    #
    def generate_secret(self, public_id):
        """
        Ask YubiHSM to generate a secret for a public_id.

        The result is stored internally in the YubiHSM in temporary memory -
        this operation would be followed by one or more generate_blob()
        commands to actually retreive the generated secret (in encrypted form).
        """
        if type(public_id) is not str:
            raise exception.YHSM_WrongInputType(
                'public_id', type(''), type(public_id))
        return secrets_cmd.YHSM_Cmd_Secrets_Generate(self.stick, public_id).execute()

    def load_secret(self, public_id, secrets):
        """
        Ask stick to load a pre-existing secret for a specific public_id.

        This is for importing keys into the HSM system.
        """
        if type(public_id) is not str:
            raise exception.YHSM_WrongInputType(
                'public_id', type(''), type(public_id))
        return secrets_cmd.YHSM_Cmd_Secrets_Load(self.stick, public_id, secrets).execute()

    def generate_blob(self, key_handle):
        """
        Ask YubiHSM to return the previously generated secret
        (see generate_secret()) encrypted with the specified key_handle.
        """
        if type(key_handle) is not int:
            assert()
        return secrets_cmd.YHSM_Cmd_Blob_Generate(self.stick, key_handle).execute()

    def validate_blob_otp(self, public_id, otp, key_handle, blob):
        """
        Ask YubiHSM to validate an OTP using a blob and a key_handle to
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
        return validate_cmd.YHSM_Cmd_Blob_Validate_OTP( \
            self.stick, public_id, otp, key_handle, blob).execute()

    #
    # Debug/testing commands.
    #
    def monitor_exit(self):
        """
        Ask YubiHSM to exit to configuration mode (requires 'debug' mode enabled).
        """
        return debug_cmd.YHSM_Cmd_Monitor_Exit(self.stick).execute()

    def get_raw_device(self):
        """
        Get the raw device. Only inteded for test code/debugging!
        """
        return self.stick.raw_device()

    def drain(self):
        """
        Read until there is nothing more to be read. Only inteded for test code/debugging!
        """
        return self.stick.drain()
