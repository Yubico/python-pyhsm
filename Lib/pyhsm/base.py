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
import time
import defines
import exception

import aead_cmd
import aes_ecb_cmd
import basic_cmd
import buffer_cmd
import db_cmd
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
        if not self.reset():
            raise exception.YHSM_Error("Initialization of YubiHSM failed")
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
        # Short sleep necessary with firmware 0.9.2. Will be removed.
        time.sleep(0.005)
        # Now verify we are in sync
        data = 'ekoeko'
        echo = self.echo(data)
        # XXX analyze 'echo' to see if we are in config mode, and produce a
        # nice exception if we are.
        return data == echo

    def set_debug(self, new):
        """
        Set debug mode (boolean).

        Returns old setting.
        """
        if type(new) is not bool:
            raise exception.YHSM_WrongInputType(
                'new', bool, type(new))
        old = self.debug
        self.debug = new
        self.stick.set_debug(new)
        return old

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

    def random_reseed(self, seed):
        """
        Provide YubiHSM DRBG_CTR with a new seed (32 bytes).
        """
        return basic_cmd.YHSM_Cmd_Random_Reseed(self.stick, seed).execute()

    def get_nonce(self, increment=1):
        """ Get current nonce from YubiHSM. """
        if type(increment) is not int:
            raise exception.YHSM_WrongInputType(
                'increment', type(1), type(increment))

        return basic_cmd.YHSM_Cmd_Nonce_Get(self.stick, increment).execute()

    #
    # AEAD related commands
    #
    def generate_secret(self, num_bytes = defines.KEY_SIZE + defines.UID_SIZE, offset = 0):
        """
        Ask YubiHSM to generate a YubiKey secret.
        """
        if type(num_bytes) is not int:
            raise exception.YHSM_WrongInputType(
                'num_bytes', type(1), type(num_bytes))
        if type(offset) is not int:
            raise exception.YHSM_WrongInputType(
                'offset', type(1), type(offset))
        return buffer_cmd.YHSM_Cmd_Secrets_Generate(self.stick, num_bytes, offset).execute()

    def load_secret(self, secrets):
        """
        Ask YubiHSM to load a pre-existing YubiKey secret.

        The result is stored internally in the YubiHSM in temporary memory -
        this operation would be followed by one or more generate_aead()
        commands to actually retreive the generated secret (in encrypted form).
        """
        return buffer_cmd.YHSM_Cmd_Buffer_Load(self.stick, secrets.pack()).execute()

    def generate_aead_simple(self, nonce, key_handle, data):
        """
        Generate AEAD block from data for a specific key in a single step
        (without using the YubiHSM internal buffer).

        `data' is either a string, or a YHSM_YubiKeySecret.
        """
        return aead_cmd.YHSM_Cmd_AEAD_Generate(self.stick, nonce, key_handle, data).execute()

    def generate_aead_random(self, nonce, key_handle, num_bytes):
        """
        Generate a random AEAD block using the YubiHSM internal TRNG.

        To generate a secret for a YubiKey, use public_id as nonce.
        """
        return aead_cmd.YHSM_Cmd_AEAD_Random_Generate(self.stick, nonce, key_handle, num_bytes).execute()

    def generate_aead(self, nonce, key_handle):
        """
        Ask YubiHSM to return the previously generated secret
        (see load_secret()) encrypted with the specified key_handle.

        For a YubiKey secret, the nonce should be the public_id.
        """
        return aead_cmd.YHSM_Cmd_AEAD_Buffer_Generate(self.stick, nonce, key_handle).execute()

    def validate_aead(self, nonce, key_handle, aead, cleartext=''):
        """
        Validate an AEAD using the YubiHSM. If cleartext is non-empty, the decrypted
        AEAD will be compared (inside the YubiHSM) to the cleartext. Otherwise, the YubiHSM
        will only check if the AEAD is intact.
        """
        return aead_cmd.YHSM_Cmd_AEAD_Decrypt_Cmp(self.stick, nonce, key_handle, aead, cleartext).execute()

    def validate_aead_otp(self, public_id, otp, key_handle, aead):
        """
        Ask YubiHSM to validate a YubiKey OTP using an AEAD and a key_handle to
        decrypt the AEAD.
        """
        if type(public_id) is not str:
            assert()
        if type(otp) is not str:
            assert()
        if type(key_handle) is not int:
            assert()
        if type(aead) is not str:
            assert()
        return validate_cmd.YHSM_Cmd_AEAD_Validate_OTP( \
            self.stick, public_id, otp, key_handle, aead).execute()

    #
    # Debug/testing commands.
    #
    def monitor_exit(self):
        """
        Ask YubiHSM to exit to configuration mode (requires 'debug' mode enabled).
        """
        return debug_cmd.YHSM_Cmd_Monitor_Exit(self.stick).execute(read_response=False)

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

        XXX make this execute() for consistency
        """
        return hmac_cmd.YHSM_Cmd_HMAC_SHA1_Write( \
            self.stick, key_handle, data, final = final)


    #
    # Internal YubiKey database related commands
    #
    def db_store_yubikey(self, public_id, key_handle, aead):
        """
        Ask YubiHSM to store data about a YubiKey in the internal database (not buffer).

        The input is an AEAD, perhaps previously created using generate_aead().
        """
        return db_cmd.YHSM_Cmd_DB_YubiKey_Store( \
            self.stick, public_id, key_handle, aead).execute()

    def db_validate_yubikey_otp(self, public_id, otp):
        """
        Request the YubiHSM to validate an OTP for a YubiKey stored
        in the internal database.
        """
        return db_cmd.YHSM_Cmd_DB_Validate_OTP( \
            self.stick, public_id, otp).execute()
