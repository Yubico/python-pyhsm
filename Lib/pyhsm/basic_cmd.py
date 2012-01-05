"""
implementations of basic commands to execute on a YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_Echo',
    'YHSM_Cmd_System_Info',
    'YHSM_Cmd_Random',
    'YHSM_Cmd_Random_Reseed',
    'YHSM_Cmd_Temp_Key_Load',
    'YHSM_Cmd_Nonce_Get',
    'YHSM_Cmd_Key_Storage_Unlock',
    'YHSM_Cmd_Key_Store_Decrypt',
    'YHSM_Cmd_HSM_Unlock',
    'YHSM_NonceResponse',
]

import pyhsm.defines
import pyhsm.exception
import pyhsm.aead_cmd
from pyhsm.cmd import YHSM_Cmd

class YHSM_Cmd_Echo(YHSM_Cmd):
    """
    Send something to the stick, and expect to get it echoed back.
    """
    def __init__(self, stick, payload=''):
        payload = pyhsm.util.input_validate_str(payload, 'payload', max_len = pyhsm.defines.YSM_MAX_PKT_SIZE - 1)
        # typedef struct {
        #   uint8_t numBytes;                   // Number of bytes in data field
        #   uint8_t data[YSM_MAX_PKT_SIZE - 1]; // Data
        # } YSM_ECHO_REQ;
        packed = chr(len(payload)) + payload
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_ECHO, packed)

    def parse_result(self, data):
        # typedef struct {
        # uint8_t numBytes;                   // Number of bytes in data field
        # uint8_t data[YSM_MAX_PKT_SIZE - 1]; // Data
        # } YSM_ECHO_RESP;
        return data[1:]


class YHSM_Cmd_System_Info(YHSM_Cmd):
    """
    Request system information from the YubiHSM.

    @ivar version_major: Major firmware version
    @ivar version_minor: Minor firmware version
    @ivar version_build: Firmware build version
    @ivar protocol_ver: Communication protocol version
    @ivar system_uid: Unique identifier for YubiHSM
    @type system_uid: string
    """

    version_major = 0
    version_minor = 0
    version_build = 0
    protocol_ver = 0
    system_uid = None

    def __init__(self, stick):
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_SYSTEM_INFO_QUERY)

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: ver=%s, proto=%s, sysid=0x%s>' % (
                self.__class__.__name__,
                hex(id(self)),
                (self.version_major, self.version_minor, self.version_build),
                self.protocol_ver,
                self.system_uid.encode('hex')
                )
        else:
            return '<%s instance at %s (not executed)>' % (
                self.__class__.__name__,
                hex(id(self))
                )

    def parse_result(self, data):
        # #define SYSTEM_ID_SIZE          12
        # typedef struct {
        #   uint8_t version_major;               // Major version #
        #   uint8_t version_minor;               // Minor version #
        #   uint8_t version_build;               // Build version #
        #   uint8_t protocolVersion;            // Protocol version #
        #   uint8_t systemUid[SYSTEM_ID_SIZE];  // System unique identifier
        # } YHSM_SYSTEM_INFO_RESP;
        self.version_major, \
            self.version_minor, \
            self.version_build, \
            self.protocol_ver, \
            self.system_uid = struct.unpack('BBBB12s', data)
        return self


class YHSM_Cmd_Random(YHSM_Cmd):
    """
    Ask stick to generate a number of random bytes.
    """
    def __init__(self, stick, num_bytes):
        self.num_bytes = pyhsm.util.input_validate_int(num_bytes, 'num_bytes', pyhsm.defines.YSM_MAX_PKT_SIZE - 1)
        # typedef struct {
        #   uint8_t numBytes;                   // Number of bytes to generate
        # } YSM_RANDOM_GENERATE_REQ;
        packed = chr(self.num_bytes)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_RANDOM_GENERATE, packed)

    def parse_result(self, data):
        # typedef struct {
        #   uint8_t numBytes;                   // Number of bytes generated
        #   uint8_t rnd[YSM_MAX_PKT_SIZE - 1];  // Random data
        # } YHSM_RANDOM_GENERATE_RESP;
        num_bytes = pyhsm.util.validate_cmd_response_int('num_bytes', ord(data[0]), self.num_bytes)
        return data[1:1 + num_bytes]


class YHSM_Cmd_Random_Reseed(YHSM_Cmd):
    """
    Provide YubiHSM DRBG_CTR with a new seed.
    """

    status = None

    def __init__(self, stick, seed):
        seed = pyhsm.util.input_validate_str(seed, 'seed', exact_len = pyhsm.defines.YSM_CTR_DRBG_SEED_SIZE)
        # #define YSM_CTR_DRBG_SEED_SIZE      32
        # typedef struct {
        #   uint8_t seed[YSM_CTR_DRBG_SEED_SIZE];   // New seed
        # } YSM_RANDOM_RESEED_REQ;
        fmt = "%is" % (pyhsm.defines.YSM_CTR_DRBG_SEED_SIZE)
        packed = struct.pack(fmt, seed)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_RANDOM_RESEED, packed)

    def parse_result(self, data):
        # typedef struct {
        #   YSM_STATUS status;                  // Status
        # } YSM_RANDOM_RESEED_RESP;
        fmt = "B"
        self.status, = struct.unpack(fmt, data)
        if self.status == pyhsm.defines.YSM_STATUS_OK:
            return True
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)


class YHSM_Cmd_Temp_Key_Load(YHSM_Cmd):
    """
    Load an AEAD into the phantom key handle 0xffffffff.

    The `aead' is either a YHSM_GeneratedAEAD, or a string.
    """

    status = None

    def __init__(self, stick, nonce, key_handle, aead):
        self.nonce = pyhsm.util.input_validate_nonce(nonce, pad = True)
        self.key_handle = pyhsm.util.input_validate_key_handle(key_handle)
        flags_size = struct.calcsize("<I")
        max_aead_len = pyhsm.defines.YSM_MAX_KEY_SIZE + flags_size + pyhsm.defines.YSM_AEAD_MAC_SIZE
        aead = pyhsm.util.input_validate_aead(aead, max_aead_len = max_aead_len)
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce
        #   uint32_t keyHandle;                 // Key handle to unlock AEAD
        #   uint8_t numBytes;                   // Number of bytes (explicit key size
        #                                       //   16, 20, 24 or 32 bytes + flags + hash)
        #   uint8_t aead[YSM_MAX_KEY_SIZE + sizeof(uint32_t) + YSM_AEAD_MAC_SIZE]; // AEAD block
        # } YSM_TEMP_KEY_LOAD_REQ;
        fmt = "< %is I B %is" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE, len(aead))
        packed = struct.pack(fmt, self.nonce, self.key_handle, len(aead), aead)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_TEMP_KEY_LOAD, packed)

    def parse_result(self, data):
        """
        Parse result of L{pyhsm.defines.YSM_TEMP_KEY_LOAD} command.

        @return: Only returns (True) on successful load
        @rtype: bool

        @raise pyhsm.exception.YHSM_CommandFailed: YubiHSM failed to load key
        """
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Status
        # } YSM_TEMP_KEY_LOAD_RESP;
        fmt = "< %is I B" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE)
        nonce, key_handle, self.status = struct.unpack(fmt, data)

        # Validate data in response against values we used in request
        pyhsm.util.validate_cmd_response_str('nonce', nonce, self.nonce)
        pyhsm.util.validate_cmd_response_hex('key_handle', key_handle, self.key_handle)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            return True
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)


class YHSM_Cmd_Nonce_Get(YHSM_Cmd):
    """
    Get nonce value from YubiHSM - causes it to increment by one (or a specified number).

    Call with post_increment 0 to just fetch current value.
    """

    status = None
    response = None

    def __init__(self, stick, post_increment):
        pyhsm.util.input_validate_int(post_increment, 'post_increment')
        # typedef struct {
        #   uint16_t postIncrement;                 // Size of increment to next nonce
        # } YSM_NONCE_GET_REQ;
        packed = struct.pack("<H", post_increment)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_NONCE_GET, packed)

    def parse_result(self, data):
        # typedef struct {
        #   YSM_STATUS status;                  // Status
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce
        # } YSM_NONCE_GET_RESP;
        fmt = "B %is" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE)
        self.status, nonce = struct.unpack(fmt, data)
        if self.status == pyhsm.defines.YSM_STATUS_OK:
            self.response = YHSM_NonceResponse(nonce)
            return self.response
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)

class YHSM_Cmd_Key_Storage_Unlock(YHSM_Cmd):
    """
    Have the YubiHSM unlock it's key storage using the HSM password.

    If an incorrect password is given when the key storage is unlocked,
    it will be locked again.

    This command was replaced by YHSM_Cmd_Key_Store_Decrypt in YubiHSM 1.0.

    @ivar status: The result of the unlock operation
    @type status: integer
    """

    status = None

    def __init__(self, stick, password=''):
        payload = pyhsm.util.input_validate_str(password, 'password', max_len = pyhsm.defines.YSM_BLOCK_SIZE)
        # typedef struct {
        #   uint8_t password[YSM_BLOCK_SIZE];  // Unlock password
        # } YSM_KEY_STORAGE_UNLOCK_REQ;
        packed = payload.ljust(pyhsm.defines.YSM_BLOCK_SIZE, chr(0x0))
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_KEY_STORAGE_UNLOCK, packed)

    def parse_result(self, data):
        """
        Parse result of L{pyhsm.defines.YSM_KEY_STORAGE_UNLOCK} command.

        @return: Only returns (True) on successful unlock
        @rtype: bool

        @raise pyhsm.exception.YHSM_CommandFailed: YubiHSM failed to unlock key storage
        """
        # typedef struct {
        #   YSM_STATUS status;                  // Unlock status
        # } YSM_KEY_STORAGE_UNLOCK_RESP;
        fmt = "B"
        self.status, = struct.unpack(fmt, data)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            return True
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)

class YHSM_Cmd_Key_Store_Decrypt(YHSM_Cmd):
    """
    Have the YubiHSM decrypt it's key store using the master key.

    If an incorrect master key is given, the key store will become unavailable
    (cleared from RAM in YubiHSM).

    @ivar status: The result of the unlock operation
    @type status: integer
    """

    status = None

    def __init__(self, stick, key=''):
        payload = pyhsm.util.input_validate_str(key, 'key', max_len = pyhsm.defines.YSM_MAX_KEY_SIZE)
        # typedef struct {
        #   uint8_t key[YSM_MAX_KEY_SIZE];      // Key store decryption key
        # } YSM_KEY_STORE_DECRYPT_REQ;
        packed = payload.ljust(pyhsm.defines.YSM_MAX_KEY_SIZE, chr(0x0))
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_KEY_STORE_DECRYPT, packed)

    def parse_result(self, data):
        """
        Parse result of L{pyhsm.defines.YSM_KEY_STORE_DECRYPT} command.

        @return: Only returns (True) on successful unlock
        @rtype: bool

        @raise pyhsm.exception.YHSM_CommandFailed: YubiHSM failed to unlock key store
        """
        # typedef struct {
        #   YSM_STATUS status;                  // Unlock status
        # } YSM_KEY_STORE_DECRYPT_RESP;
        fmt = "B"
        self.status, = struct.unpack(fmt, data)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            return True
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)

class YHSM_Cmd_HSM_Unlock(YHSM_Cmd):
    """
    Have the YubiHSM unlock the HSM operations (those involving the keystore) with a YubiKey OTP.

    Admin YubiKeys public id's are entered during initial configuration. These must then be made
    available in the internal database.

    @ivar status: The result of the unlock operation
    @type status: integer
    """

    status = None

    def __init__(self, stick, public_id, otp):
        self.public_id = pyhsm.util.input_validate_nonce(public_id, pad = True)
        self.otp = pyhsm.util.input_validate_str(otp, 'otp', exact_len = pyhsm.defines.YSM_OTP_SIZE)
        # typedef struct {
        #   uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id
        #   uint8_t otp[YSM_OTP_SIZE];          // OTP
        # } YSM_HSM_UNLOCK_REQ;
        fmt = "< %is %is" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE, \
                                       pyhsm.defines.YSM_OTP_SIZE, \
                                 )
        packed = struct.pack(fmt, self.public_id, \
                                 self.otp,
                             )
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_HSM_UNLOCK, packed)

    def parse_result(self, data):
        """
        Parse result of L{pyhsm.defines.YSM_HSM_UNLOCK} command.

        @return: Only returns (True) on successful unlock
        @rtype: bool

        @raise pyhsm.exception.YHSM_CommandFailed: YubiHSM failed to unlock key store
        """
        # typedef struct {
        #   YSM_STATUS status;                  // Unlock status
        # } YSM_HSM_UNLOCK_RESP;
        fmt = "B"
        self.status, = struct.unpack(fmt, data)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            return True
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)

class YHSM_NonceResponse():
    """ Small class to hold response of Nonce_Get command.

    @ivar volatile: Volatile part of nonce
    @ivar pu_count: Power-up count -- persistent part of nonce
    @ivar nonce_int: Current nonce
    @ivar nonce: Current nonce

    @type volatile: integer
    @type pu_count: integer
    @type nonce_int: long
    @type nonce: string
    """
    volatile = 0
    pu_count = 0
    nonce_int = 0
    nonce = None

    def __init__(self, nonce):
        # The power-up count can be deduced from the nonce =)
        self.volatile = struct.unpack("<L", nonce[0:4])[0]
        self.pu_count = struct.unpack("<H", nonce[4:6])[0]
        self.nonce_int = (self.pu_count << 32) + self.volatile
        self.nonce = nonce

    def __repr__(self):
        return '<%s instance at %s: nonce=%s, pu_count=%i, volatile=%i>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.nonce.encode('hex'),
            self.pu_count,
            self.volatile
            )
