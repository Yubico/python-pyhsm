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

import time

__all__ = [
    # constants
    # functions
    # classes
    'YHSM'
]

#from pyhsm  import __version__
import pyhsm.cmd
import pyhsm.stick
import pyhsm.exception

import pyhsm.aead_cmd
import pyhsm.aes_ecb_cmd
import pyhsm.basic_cmd
import pyhsm.buffer_cmd
import pyhsm.db_cmd
import pyhsm.debug_cmd
import pyhsm.hmac_cmd
import pyhsm.validate_cmd

class YHSM():
    """
    Base class for accessing YubiHSM
    """

    def __init__(self, device, debug=False, timeout=1):
        self.debug = debug
        self.stick = pyhsm.stick.YHSM_Stick(device, debug = self.debug, timeout = timeout)
        if not self.reset():
            raise pyhsm.exception.YHSM_Error("Initialization of YubiHSM failed")
        return None

    def __repr__(self):
        return '<%s instance at %s: %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.stick.device
            )

    def reset(self):
        """ Perform stream resynchronization. Return True if successful. """
        pyhsm.cmd.reset(self.stick)
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
            raise pyhsm.exception.YHSM_WrongInputType(
                'new', bool, type(new))
        old = self.debug
        self.debug = new
        self.stick.set_debug(new)
        return old

    #
    # Basic commands
    #
    def echo(self, data):
        """
        Echo test.

        `data' is a string.
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Echo(self.stick, data).execute()

    def info(self):
        """ Get firmware version and unique ID from YubiHSM. """
        return pyhsm.basic_cmd.YHSM_Cmd_System_Info(self.stick).execute()

    def random(self, num_bytes):
        """
        Get random bytes from YubiHSM.

        `num_bytes' is an integer.
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Random(self.stick, num_bytes).execute()

    def random_reseed(self, seed):
        """
        Provide YubiHSM DRBG_CTR with a new seed.

        `seed' is a string of length 32.
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Random_Reseed(self.stick, seed).execute()

    def get_nonce(self, increment=1):
        """
        Get current nonce from YubiHSM.

        `increment' is an optional integer (default: 1).
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Nonce_Get(self.stick, increment).execute()

    def load_temp_key(self, nonce, key_handle, aead):
        """
        Load an AEAD into the phantom key handle 0xffffffff.

        The `aead' is either a YHSM_GeneratedAEAD, or a string.
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Temp_Key_Load(self.stick, nonce, key_handle, aead).execute()

    #
    # AEAD related commands
    #
    def load_secret(self, secret):
        """
        Ask YubiHSM to load a pre-existing YubiKey secret.

        The result is stored internally in the YubiHSM in temporary memory -
        this operation would be followed by one or more generate_aead()
        commands to actually retreive the generated secret (in encrypted form).
        """
        if isinstance(secret, pyhsm.aead_cmd.YHSM_YubiKeySecret):
            secret = secret.pack()
        return pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Load(self.stick, secret).execute()

    def load_random(self, num_bytes, offset = 0):
        """
        Ask YubiHSM to load random data into the internal buffer.

        The result is stored internally in the YubiHSM in temporary memory -
        this operation would be followed by one or more generate_aead()
        commands to actually retreive the generated secret (in encrypted form).
        """
        return pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Random_Load(self.stick, num_bytes, offset).execute()

    def generate_aead_simple(self, nonce, key_handle, data):
        """
        Generate AEAD block from data for a specific key in a single step
        (without using the YubiHSM internal buffer).

        `data' is either a string, or a YHSM_YubiKeySecret.
        """
        return pyhsm.aead_cmd.YHSM_Cmd_AEAD_Generate(self.stick, nonce, key_handle, data).execute()

    def generate_aead_random(self, nonce, key_handle, num_bytes):
        """
        Generate a random AEAD block using the YubiHSM internal TRNG.

        To generate a secret for a YubiKey, use public_id as nonce.
        """
        return pyhsm.aead_cmd.YHSM_Cmd_AEAD_Random_Generate(self.stick, nonce, key_handle, num_bytes).execute()

    def generate_aead(self, nonce, key_handle):
        """
        Ask YubiHSM to return the previously generated secret
        (see load_secret()) encrypted with the specified key_handle.

        For a YubiKey secret, the nonce should be the public_id.
        """
        return pyhsm.aead_cmd.YHSM_Cmd_AEAD_Buffer_Generate(self.stick, nonce, key_handle).execute()

    def validate_aead(self, nonce, key_handle, aead, cleartext):
        """
        Validate an AEAD using the YubiHSM. The cleartext should be of the same length as
        the AEAD minus the size of the MAC (8 bytes).
        """
        return pyhsm.aead_cmd.YHSM_Cmd_AEAD_Decrypt_Cmp(self.stick, nonce, key_handle, aead, cleartext).execute()

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
        return pyhsm.validate_cmd.YHSM_Cmd_AEAD_Validate_OTP( \
            self.stick, public_id, otp, key_handle, aead).execute()

    #
    # Debug/testing commands.
    #
    def monitor_exit(self):
        """
        Ask YubiHSM to exit to configuration mode (requires 'debug' mode enabled).
        """
        return pyhsm.debug_cmd.YHSM_Cmd_Monitor_Exit(self.stick).execute(read_response=False)

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
        return pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Encrypt( \
            self.stick, key_handle, plaintext).execute()

    def aes_ecb_decrypt(self, key_handle, ciphertext):
        """
        AES ECB decrypt using a key handle.
        """
        return pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Decrypt( \
            self.stick, key_handle, ciphertext).execute()

    def aes_ecb_compare(self, key_handle, ciphertext, plaintext):
        """
        AES ECB decrypt and then compare using a key handle.
        """
        return pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Compare( \
            self.stick, key_handle, ciphertext, plaintext).execute()

    #
    # HMAC commands
    #
    def hmac_sha1(self, key_handle, data, final = True):
        """
        Have the YubiHSM generate a HMAC SHA1 of 'data' using a key handle.
        """
        return pyhsm.hmac_cmd.YHSM_Cmd_HMAC_SHA1_Write( \
            self.stick, key_handle, data, final = final).execute()


    #
    # Internal YubiKey database related commands
    #
    def db_store_yubikey(self, public_id, key_handle, aead):
        """
        Ask YubiHSM to store data about a YubiKey in the internal database (not buffer).

        The input is an AEAD, perhaps previously created using generate_aead().
        """
        return pyhsm.db_cmd.YHSM_Cmd_DB_YubiKey_Store( \
            self.stick, public_id, key_handle, aead).execute()

    def db_validate_yubikey_otp(self, public_id, otp):
        """
        Request the YubiHSM to validate an OTP for a YubiKey stored
        in the internal database.
        """
        return pyhsm.db_cmd.YHSM_Cmd_DB_Validate_OTP( \
            self.stick, public_id, otp).execute()
