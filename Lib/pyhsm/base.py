#
# Copyright (c) 2011, Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
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

import aes_ecb_cmd
import basic_cmd
import debug_cmd
import hmac_cmd
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

    #
    # AES ECB commands
    #
    def aes_ecb_encrypt(self, key_handle, plaintext):
        """
        AES ECB encrypt using a key handle.
        """
        return aes_ecb_cmd.YHSM_Cmd_AES_ECB_Encrypt( \
            self.stick, key_handle, plaintext).execute()

    def aes_ecb_decrypt(self, key_handle, ciphertext):
        """
        AES ECB decrypt using a key handle.
        """
        return aes_ecb_cmd.YHSM_Cmd_AES_ECB_Decrypt( \
            self.stick, key_handle, ciphertext).execute()

    def aes_ecb_compare(self, key_handle, ciphertext, plaintext):
        """
        AES ECB decrypt and then compare using a key handle.
        """
        return aes_ecb_cmd.YHSM_Cmd_AES_ECB_Compare( \
            self.stick, key_handle, ciphertext, plaintext).execute()

    #
    # HMAC commands
    #
    def hmac_sha1(self, key_handle, data, final = True):
        """
        Have the YubiHSM generate a HMAC SHA1 of 'data' using a key handle.
        """
        return hmac_cmd.YHSM_Cmd_HMAC_SHA1_Write( \
            self.stick, key_handle, data, final = final)
