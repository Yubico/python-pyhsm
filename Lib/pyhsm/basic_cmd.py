"""
implementations of basic commands to execute on a YubiHSM

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_Echo',
    'YHSM_Cmd_System_Info',
    'YHSM_Cmd_Random',
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
    Request system information from the stick.
    """
    def __init__(self, stick):
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_SYSTEM_INFO_QUERY)
        self.version_major = 0
        self.version_minor = 0
        self.version_build = 0
        self.protocol_ver = 0
        self.system_uid = None

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
        seed = pyhsm.util.input_validate_str(seed, 'seed', exact_len = pyhsm.defines.CTR_DRBG_SEED_SIZE)
        # #define CTR_DRBG_SEED_SIZE      32
        # typedef struct {
        #   uint8_t seed[CTR_DRBG_SEED_SIZE];   // New seed
        # } YSM_RANDOM_RESEED_REQ;
        fmt = "%is" % (pyhsm.defines.CTR_DRBG_SEED_SIZE)
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
        self.nonce = pyhsm.util.input_validate_nonce(nonce)
        self.key_handle = pyhsm.util.input_validate_key_handle(key_handle)
        aead = pyhsm.util.input_validate_aead(aead)
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce
        #   uint32_t keyHandle;                 // Key handle to unlock AEAD
        #   uint8_t numBytes;                   // Number of bytes (explicit key size 16, 20, 24 or 32 bytes + hash)
        #   uint8_t aead[YSM_MAX_KEY_SIZE + YSM_AEAD_MAC_SIZE]; // AEAD block
        # } YSM_TEMP_KEY_LOAD_REQ;
        max_aead_len = pyhsm.defines.YSM_MAX_KEY_SIZE + pyhsm.defines.YSM_AEAD_MAC_SIZE
        fmt = "< %is I B %is" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE, max_aead_len)
        packed = struct.pack(fmt, self.nonce, self.key_handle, len(aead), aead)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_TEMP_KEY_LOAD, packed)

    def parse_result(self, data):
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
    """

    status = None
    response = None

    def __init__(self, stick, increment):
        pyhsm.util.input_validate_int(increment, 'increment')
        # typedef struct {
        #   uint16_t increment;                 // Size of increment to next nonce
        # } YSM_NONCE_GET_REQ;
        packed = struct.pack("<H", increment)
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


class YHSM_NonceResponse():
    """ Small class to hold response of Nonce_Get command. """
    def __init__(self, nonce):
        # The power-up count can be deduced from the nonce =)
        self.volatile = struct.unpack("<L", nonce[0:4])[0]
        self.pu_count = struct.unpack("<H", nonce[4:6])[0]
        self.nonce = (self.pu_count << 32) + self.volatile

    def __repr__(self):
        return '<%s instance at %s: nonce=%i, pu_count=%i, volatile=%i>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.nonce,
            self.pu_count,
            self.volatile
            )
