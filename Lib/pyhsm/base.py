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
    Base class for accessing a YubiHSM.
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
        """
        Perform stream resynchronization.

        @return: True if successful
        @rtype: bool
        """
        pyhsm.cmd.reset(self.stick)
        # Now verify we are in sync
        data = 'ekoeko'
        echo = self.echo(data)
        # XXX analyze 'echo' to see if we are in config mode, and produce a
        # nice exception if we are.
        return data == echo

    def set_debug(self, new):
        """
        Set debug mode.

        @param new: new value
        @type new: bool

        @return: old value
        @rtype: bool
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

        @type data: string
        @return: data read from YubiHSM -- should equal `data'
        @rtype: string

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Echo.parse_result}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Echo(self.stick, data).execute()

    def info(self):
        """ Get firmware version and unique ID from YubiHSM.

        @return: System information
        @rtype: L{YHSM_Cmd_System_Info}

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_System_Info.parse_result}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_System_Info(self.stick).execute()

    def random(self, num_bytes):
        """
        Get random bytes from YubiHSM.

        The random data is DRBG_CTR seeded on each startup by a hardware TRNG,
        so it should be of very good quality.

        @type num_bytes: integer

        @return: Bytes with random data
        @rtype: string

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Random.parse_result}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Random(self.stick, num_bytes).execute()

    def random_reseed(self, seed):
        """
        Provide YubiHSM DRBG_CTR with a new seed.

        @param seed: new seed -- must be exactly 32 bytes
        @type seed: string
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Random_Reseed(self.stick, seed).execute()

    def get_nonce(self, increment=1):
        """
        Get current nonce from YubiHSM.

        Use increment 0 to just fetch the value without incrementing it.

        @keyword increment: requested increment (optional)

        @return: nonce value _before_ increment
        @rtype: L{YHSM_NonceResponse}

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Nonce_Get.parse_result}
       """
        return pyhsm.basic_cmd.YHSM_Cmd_Nonce_Get(self.stick, increment).execute()

    def load_temp_key(self, nonce, key_handle, aead):
        """
        Load the contents of an AEAD into the phantom key handle 0xffffffff.

        @param nonce: The nonce used when creating the AEAD
        @param key_handle: The key handle that can decrypt the AEAD
        @param aead: AEAD containing the cryptographic key and permission flags
        @type nonce: string
        @type key_handle: integer or string
        @type aead: L{YHSM_GeneratedAEAD} or string

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Temp_Key_Load.parse_result}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Temp_Key_Load(self.stick, nonce, key_handle, aead).execute()

    def key_storage_unlock(self, password):
        """
        Have the YubiHSM unlock it's key storage using the HSM password.

        @param password: The HSM password set during YubiHSM configuration
        @type password: string

        @returns: Only returns (True) on success
        @rtype: bool

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Key_Storage_Unlock.parse_result}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Key_Storage_Unlock(self.stick, password).execute()

    #
    # AEAD related commands
    #
    def load_secret(self, secret):
        """
        Ask YubiHSM to load a pre-existing YubiKey secret.

        The data is stored internally in the YubiHSM in temporary memory -
        this operation would typically be followed by one or more L{generate_aead}
        commands to actually retreive the generated secret (in encrypted form).

        @param secret: YubiKey secret to load
        @type secret: L{pyhsm.aead_cmd.YHSM_YubiKeySecret} or string

        @returns: Number of bytes in YubiHSM internal buffer after load
        @rtype: integer

        @see: L{pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Load.parse_result}
        """
        if isinstance(secret, pyhsm.aead_cmd.YHSM_YubiKeySecret):
            secret = secret.pack()
        return pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Load(self.stick, secret).execute()

    def load_data(self, data, offset):
        """
        Ask YubiHSM to load arbitrary data into it's internal buffer, at any offset.

        The data is stored internally in the YubiHSM in temporary memory -
        this operation would typically be followed by one or more L{generate_aead}
        commands to actually retreive the generated secret (in encrypted form).

        Load data to offset 0 to reset the buffer.

        @param data: arbitrary data to load
        @type data: string

        @returns: Number of bytes in YubiHSM internal buffer after load
        @rtype: integer

        @see: L{pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Load.parse_result}
        """
        return pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Load(self.stick, data, offset).execute()

    def load_random(self, num_bytes, offset = 0):
        """
        Ask YubiHSM to generate a number of random bytes to any offset of it's internal
        buffer.

        The data is stored internally in the YubiHSM in temporary memory -
        this operation would typically be followed by one or more L{generate_aead}
        commands to actually retreive the generated secret (in encrypted form).

        @param num_bytes: Number of bytes to generate
        @type num_bytes: integer

        @returns: Number of bytes in YubiHSM internal buffer after load
        @rtype: integer

        @see: L{pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Random_Load.parse_result}
        """
        return pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Random_Load(self.stick, num_bytes, offset).execute()

    def generate_aead_simple(self, nonce, key_handle, data):
        """
        Generate AEAD block from data for a specific key in a single step
        (without using the YubiHSM internal buffer).

        @param nonce: The nonce to use when creating the AEAD
        @param key_handle: The key handle that can encrypt data into an AEAD
        @param data: Data to put inside the AEAD
        @type nonce: string
        @type key_handle: integer or string
        @type data: string

        @returns: The generated AEAD on success.
        @rtype: L{YHSM_GeneratedAEAD}

        @see: L{pyhsm.aead_cmd.YHSM_Cmd_AEAD_Generate.parse_result}
        """
        return pyhsm.aead_cmd.YHSM_Cmd_AEAD_Generate(self.stick, nonce, key_handle, data).execute()

    def generate_aead_random(self, nonce, key_handle, num_bytes):
        """
        Generate a random AEAD block using the YubiHSM internal DRBG_CTR random generator.

        To generate a secret for a YubiKey, use public_id as nonce.

        @param nonce: The nonce to use when creating the AEAD
        @param key_handle: The key handle that can encrypt the random data into an AEAD
        @param num_bytes: Number of random data bytes to put inside the AEAD
        @type nonce: string
        @type key_handle: integer or string
        @type num_bytes: integer

        @returns: The generated AEAD on success.
        @rtype: L{YHSM_GeneratedAEAD}

        @see: L{pyhsm.aead_cmd.YHSM_Cmd_AEAD_Random_Generate.parse_result}
        """
        return pyhsm.aead_cmd.YHSM_Cmd_AEAD_Random_Generate(self.stick, nonce, key_handle, num_bytes).execute()

    def generate_aead(self, nonce, key_handle):
        """
        Ask YubiHSM to return an AEAD made of the contents of it's internal buffer
        (see L{load_secret}, L{load_data} and L{load_random}) encrypted with the specified key_handle.

        For a YubiKey secret, the nonce should be the public_id.

        @param nonce: The nonce to use when creating the AEAD
        @param key_handle: The key handle that can create an AEAD
        @type nonce: string
        @type key_handle: integer or string

        @returns: The generated AEAD on success.
        @rtype: L{YHSM_GeneratedAEAD}

        @see: L{pyhsm.aead_cmd.YHSM_Cmd_AEAD_Buffer_Generate.parse_result}
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
        Get the raw device. Only intended for test code/debugging!
        """
        return self.stick.raw_device()

    def drain(self):
        """
        Read until there is nothing more to be read. Only intended for test code/debugging!
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
    def hmac_sha1(self, key_handle, data, flags = None, final = True, to_buffer = False):
        """
        Have the YubiHSM generate a HMAC SHA1 of 'data' using a key handle.
        """
        return pyhsm.hmac_cmd.YHSM_Cmd_HMAC_SHA1_Write( \
            self.stick, key_handle, data, flags = flags, final = final, to_buffer = to_buffer).execute()


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
