#
# Copyright (c) 2011 Yubico AB
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

__all__ = [
    # constants
    # functions
    # classes
    'YHSM'
]

#from pyhsm  import __version__
import pyhsm.cmd
import pyhsm.stick
import pyhsm.stick_client
import pyhsm.exception
import pyhsm.version

import pyhsm.aead_cmd
import pyhsm.aes_ecb_cmd
import pyhsm.basic_cmd
import pyhsm.buffer_cmd
import pyhsm.db_cmd
import pyhsm.debug_cmd
import pyhsm.hmac_cmd
import pyhsm.validate_cmd

import pyhsm.yubikey
import pyhsm.soft_hsm

class YHSM():
    """
    Base class for accessing a YubiHSM.
    """

    def __init__(self, device, debug=False, timeout=1, test_comm=True):
        self.debug = debug
        if device.startswith('yhsm://'):
            self.stick = pyhsm.stick_client.YHSM_Stick_Client(device)
        else:
            self.stick = pyhsm.stick.YHSM_Stick(device, debug = self.debug, timeout = timeout)

        if not self.reset(test_sync = False):
            raise pyhsm.exception.YHSM_Error("Initialization of YubiHSM failed")
        self.version = pyhsm.version.YHSM_Version(self.info())
        # Check that this is a device we know how to talk to
        if self.version.sysinfo.protocol_ver != pyhsm.defines.YSM_PROTOCOL_VERSION:
            raise pyhsm.exception.YHSM_Error("Unknown YubiHSM protocol version (%i, I speak %i)" % \
                                                 (self.version.sysinfo.protocol_ver, \
                                                      pyhsm.defines.YSM_PROTOCOL_VERSION))
        # Check that communication isn't mangled (by something like 'stty onlcr')
        if test_comm:
            self.test_comm()
        return None

    def __repr__(self):
        return '<%s instance at %s: %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.stick.device
            )

    def reset(self, test_sync = True):
        """
        Perform stream resynchronization.

        @param test_sync: Verify sync with YubiHSM after reset
        @type test_sync: bool

        @return: True if successful
        @rtype: bool
        """
        pyhsm.cmd.reset(self.stick)
        if test_sync:
            # Now verify we are in sync
            data = 'ekoeko'
            echo = self.echo(data)
            # XXX analyze 'echo' to see if we are in config mode, and produce a
            # nice exception if we are.
            return data == echo
        else:
            return True

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

    def test_comm(self):
        """
        Verify that data we send to and receive from the YubiHSM isn't mangled.

        In some scenarios, communications with the YubiHSM might be affected
        by terminal line settings turning CR into LF for example.
        """
        data = ''.join([chr(x) for x in range(256)])
        data = data + '0d0a0d0a'.decode('hex')
        chunk_size = pyhsm.defines.YSM_MAX_PKT_SIZE - 10 # max size of echo
        count = 0
        while data:
            this = data[:chunk_size]
            data = data[chunk_size:]
            res = self.echo(this)
            for i in xrange(len(this)):
                if res[i] != this[i]:
                    msg = "Echo test failed at position %i (0x%x != 0x%x)" \
                        % (count + i, ord(res[i]), ord(this[i]))
                    raise pyhsm.exception.YHSM_Error(msg)
            count += len(this)

    #
    # Basic commands
    #
    def echo(self, data):
        """
        Echo test.

        @type data: string
        @return: data read from YubiHSM -- should equal `data'
        @rtype: string

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Echo}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Echo(self.stick, data).execute()

    def info(self):
        """ Get firmware version and unique ID from YubiHSM.

        @return: System information
        @rtype: L{YHSM_Cmd_System_Info}

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_System_Info}
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

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Random}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Random(self.stick, num_bytes).execute()

    def random_reseed(self, seed):
        """
        Provide YubiHSM DRBG_CTR with a new seed.

        @param seed: new seed -- must be exactly 32 bytes
        @type seed: string

        @returns: True on success
        @rtype: bool

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Random_Reseed}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Random_Reseed(self.stick, seed).execute()

    def get_nonce(self, increment=1):
        """
        Get current nonce from YubiHSM.

        Use increment 0 to just fetch the value without incrementing it.

        @keyword increment: requested increment (optional)

        @return: nonce value _before_ increment
        @rtype: L{YHSM_NonceResponse}

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Nonce_Get}
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

        @returns: True on success
        @rtype: bool

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Temp_Key_Load}
        """
        return pyhsm.basic_cmd.YHSM_Cmd_Temp_Key_Load(self.stick, nonce, key_handle, aead).execute()

    def unlock(self, password = None, otp = None):
        """
        Unlock the YubiHSM using the master key and/or a YubiKey OTP.

        If the master key is given during configuration, all key handles will be
        encrypted (with AES-256) using that passphrase.

        If one or more admin Yubikey public id's are given during configuration,
        an OTP from one of these must be provided to the YubiHSM for it to start
        responding to cryptographic requests. The admin YubiKeys must be present
        in the internal database for this validation to work.

        @param password: The 'master key' set during YubiHSM configuration
        @type password: NoneType or string
        @param otp: A YubiKey OTP from an 'admin' YubiKey (modhex), to unlock YubiHSM.
        @type otp: NoneType or string

        @returns: Only returns (True) on success
        @rtype: bool

        @see: L{pyhsm.basic_cmd.YHSM_Cmd_Key_Storage_Unlock}
        @see: L{pyhsm.basic_cmd.YHSM_Cmd_HSM_Unlock}
        """
        if otp is not None and not self.version.have_unlock():
            # only in 1.0
            raise pyhsm.exception.YHSM_Error("Your YubiHSM does not support OTP unlocking.")
        if password is not None:
            if self.version.have_key_storage_unlock():
                # 0.9.x
                res = pyhsm.basic_cmd.YHSM_Cmd_Key_Storage_Unlock(self.stick, password).execute()
            elif self.version.have_key_store_decrypt():
                # 1.0
                res = pyhsm.basic_cmd.YHSM_Cmd_Key_Store_Decrypt(self.stick, password).execute()
            else:
                raise pyhsm.exception.YHSM_Error("Don't know how to unlock your YubiHSM.")
        else:
            res = True
        if res and otp is not None:
            (public_id, otp,) = pyhsm.yubikey.split_id_otp(otp)
            public_id = pyhsm.yubikey.modhex_decode(public_id).decode('hex')
            otp = pyhsm.yubikey.modhex_decode(otp).decode('hex')
            return pyhsm.basic_cmd.YHSM_Cmd_HSM_Unlock(self.stick, public_id, otp).execute()
        return res

    def key_storage_unlock(self, password):
        """
        @deprecated: Too specific (and hard to remember) name.
        @see: L{unlock}
        """
        return self.unlock(password = password)

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

        @see: L{pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Load}
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

        @see: L{pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Load}
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

        @see: L{pyhsm.buffer_cmd.YHSM_Cmd_Buffer_Random_Load}
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

        @see: L{pyhsm.aead_cmd.YHSM_Cmd_AEAD_Generate}
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

        @see: L{pyhsm.aead_cmd.YHSM_Cmd_AEAD_Random_Generate}
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

        @see: L{pyhsm.aead_cmd.YHSM_Cmd_AEAD_Buffer_Generate}
        """
        return pyhsm.aead_cmd.YHSM_Cmd_AEAD_Buffer_Generate(self.stick, nonce, key_handle).execute()

    def validate_aead(self, nonce, key_handle, aead, cleartext):
        """
        Validate the contents of an AEAD using the YubiHSM. The matching is done
        inside the YubiHSM so the contents of the AEAD is never exposed (well,
        except indirectionally when the cleartext does match).

        The cleartext should naturally be of the same length as the AEAD minus
        the size of the MAC (8 bytes).

        @param nonce: The nonce used when creating the AEAD
        @param key_handle: The key handle that can decrypt the AEAD
        @param aead: AEAD containing the cryptographic key and permission flags
        @param cleartext: The presumed cleartext of the AEAD
        @type nonce: string
        @type key_handle: integer or string
        @type aead: L{YHSM_GeneratedAEAD} or string
        @type cleartext: string

        @returns: Whether or not the cleartext matches the contents of the AEAD.
        @rtype: bool

        @see: L{pyhsm.aead_cmd.YHSM_Cmd_AEAD_Decrypt_Cmp}
        """
        return pyhsm.aead_cmd.YHSM_Cmd_AEAD_Decrypt_Cmp(self.stick, nonce, key_handle, aead, cleartext).execute()

    def validate_aead_otp(self, public_id, otp, key_handle, aead):
        """
        Ask YubiHSM to validate a YubiKey OTP using an AEAD and a key_handle to
        decrypt the AEAD.

        @param public_id: The six bytes public id of the YubiKey
        @param otp: The one time password (OTP) to validate
        @param key_handle: The key handle that can decrypt the AEAD
        @param aead: AEAD containing the cryptographic key and permission flags
        @type public_id: string
        @type otp: string
        @type key_handle: integer or string
        @type aead: L{YHSM_GeneratedAEAD} or string

        @returns: validation response
        @rtype: L{YHSM_ValidationResult}

        @see: L{pyhsm.validate_cmd.YHSM_Cmd_AEAD_Validate_OTP}
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

        @returns: None
        @rtype: NoneType

        @see: L{pyhsm.debug_cmd.YHSM_Cmd_Monitor_Exit}
        """
        return pyhsm.debug_cmd.YHSM_Cmd_Monitor_Exit(self.stick).execute(read_response=False)

    def get_raw_device(self):
        """
        Get the raw device. Only intended for test code/debugging!

        @returns: serial device
        @rtype: Serial
        """
        return self.stick.raw_device()

    def drain(self):
        """
        Read until there is nothing more to be read. Only intended for test code/debugging!

        @returns: True on success
        @rtype: bool
        """
        try:
            unlock = self.stick.acquire()
            return self.stick.drain()
        finally:
            unlock()

    #
    # AES ECB commands
    #
    def aes_ecb_encrypt(self, key_handle, plaintext):
        """
        AES ECB encrypt using a key handle.

        @warning: Please be aware of the known limitations of AES ECB mode before using it!

        @param key_handle: Key handle to use for AES ECB encryption
        @param plaintext: Data to encrypt
        @type key_handle: integer or string
        @type plaintext: string

        @returns: Ciphertext
        @rtype: string

        @see: L{pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Encrypt}
        """
        return pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Encrypt( \
            self.stick, key_handle, plaintext).execute()

    def aes_ecb_decrypt(self, key_handle, ciphertext):
        """
        AES ECB decrypt using a key handle.

        @warning: Please be aware of the known limitations of AES ECB mode before using it!

        @param key_handle: Key handle to use for AES ECB decryption
        @param ciphertext: Data to decrypt
        @type key_handle: integer or string
        @type ciphertext: string

        @returns: Plaintext
        @rtype: string

        @see: L{pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Decrypt}
        """
        return pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Decrypt( \
            self.stick, key_handle, ciphertext).execute()

    def aes_ecb_compare(self, key_handle, ciphertext, plaintext):
        """
        AES ECB decrypt and then compare using a key handle.

        The comparison is done inside the YubiHSM so the plaintext is never exposed (well,
        except indirectionally when the provided plaintext does match).

        @warning: Please be aware of the known limitations of AES ECB mode before using it!

        @param key_handle: Key handle to use for AES ECB decryption
        @param plaintext: Data to decrypt
        @type key_handle: integer or string
        @type plaintext: string

        @returns: Match result
        @rtype: bool

        @see: L{pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Compare}
        """
        return pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB_Compare( \
            self.stick, key_handle, ciphertext, plaintext).execute()

    #
    # HMAC commands
    #
    def hmac_sha1(self, key_handle, data, flags = None, final = True, to_buffer = False):
        """
        Have the YubiHSM generate a HMAC SHA1 of 'data' using a key handle.

        Use the L{pyhsm.hmac_cmd.YHSM_Cmd_HMAC_SHA1_Write.next} to add more input (until
        'final' has been set to True).

        Use the L{pyhsm.hmac_cmd.YHSM_Cmd_HMAC_SHA1_Write.get_hash} to get the hash result
        this far.

        @param key_handle: Key handle to use when generating HMAC SHA1
        @param data: what to calculate the HMAC SHA1 checksum of
        @keyword flags: bit-flags, overrides 'final' and 'to_buffer'
        @keyword final: True when there is no more data, False if there is more
        @keyword to_buffer: Should the final result be stored in the YubiHSM internal buffer or not
        @type key_handle: integer or string
        @type data: string
        @type flags: None or integer

        @returns: HMAC-SHA1 instance
        @rtype: L{YHSM_Cmd_HMAC_SHA1_Write}

        @see: L{pyhsm.hmac_cmd.YHSM_Cmd_HMAC_SHA1_Write}
        """
        return pyhsm.hmac_cmd.YHSM_Cmd_HMAC_SHA1_Write( \
            self.stick, key_handle, data, flags = flags, final = final, to_buffer = to_buffer).execute()


    #
    # Internal YubiKey database related commands
    #
    def db_store_yubikey(self, public_id, key_handle, aead, nonce = None):
        """
        Ask YubiHSM to store data about a YubiKey in the internal database (not buffer).

        The input is an AEAD with the secrets of a YubiKey, perhaps previously created
        using L{load_secret}.

        @param public_id: The six bytes public id of the YubiKey
        @param key_handle: Key handle that can decrypt the YubiKey AEAD
        @param aead: AEAD of an L{pyhsm.aead_cmd.YHSM_YubiKeySecret}
        @param nonce: Nonce, if different from public_id.
        @type public_id: string
        @type key_handle: integer or string
        @type aead: L{YHSM_GeneratedAEAD} or string
        @type nonce: None or string

        @return: True on success
        @rtype: bool

        @see: L{pyhsm.db_cmd.YHSM_Cmd_DB_YubiKey_Store}
        """
        if nonce is not None and not self.version.have_YSM_DB_YUBIKEY_AEAD_STORE2():
            # introduced in 1.0.4
            raise pyhsm.exception.YHSM_Error("YubiHSM does not support nonce != public_id.")
        return pyhsm.db_cmd.YHSM_Cmd_DB_YubiKey_Store( \
            self.stick, public_id, key_handle, aead, nonce = nonce).execute()

    def db_validate_yubikey_otp(self, public_id, otp):
        """
        Request the YubiHSM to validate an OTP for a YubiKey stored
        in the internal database.

        @param public_id: The six bytes public id of the YubiKey
        @param otp: The OTP from a YubiKey in binary form (16 bytes)
        @type public_id: string
        @type otp: string

        @returns: validation response
        @rtype: L{YHSM_ValidationResult}

        @see: L{pyhsm.db_cmd.YHSM_Cmd_DB_Validate_OTP}
        """
        return pyhsm.db_cmd.YHSM_Cmd_DB_Validate_OTP( \
            self.stick, public_id, otp).execute()
