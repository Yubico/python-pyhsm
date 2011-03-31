"""
implementations of basic commands to execute on a YubiHSM

"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines
import exception

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_Echo',
    'YHSM_Cmd_System_Info',
    'YHSM_Cmd_Random',
]

from cmd import YHSM_Cmd

class YHSM_Cmd_Echo(YHSM_Cmd):
    """
    Send something to the stick, and expect to get it echoed back.
    """
    def __init__(self, stick, payload=''):
        if len(payload) > defines.YSM_MAX_PKT_SIZE - 1:
            raise exception.YHSM_InputTooLong(
                'payload', defines.YSM_MAX_PKT_SIZE - 1, len(data))
        packed = chr(len(payload)) + payload
        YHSM_Cmd.__init__(self, stick, defines.YSM_ECHO, packed)

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
        YHSM_Cmd.__init__(self, stick, defines.YSM_SYSTEM_INFO_QUERY)
        self.version_major = 0
        self.version_minor = 0
        self.version_build = 0
        self.protocolVersion = 0
        self.systemUid = None

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: ver=%s, proto=%s, sysid=0x%s>' % (
                self.__class__.__name__,
                hex(id(self)),
                (self.version_major, self.version_minor, self.version_build),
                self.protocolVersion,
                self.systemUid.encode('hex')
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
            self.protocolVersion, \
            self.systemUid = struct.unpack('BBBB12s', data)
        return self


class YHSM_Cmd_Random(YHSM_Cmd):
    """
    Ask stick to generate a number of random bytes.
    """
    def __init__(self, stick, num_bytes):
        self.num_bytes = num_bytes
        packed = chr(self.num_bytes)
        YHSM_Cmd.__init__(self, stick, defines.YSM_RANDOM_GENERATE, packed)

    def parse_result(self, data):
        # typedef struct {
        #   uint8_t numBytes;                   // Number of bytes generated
        #   uint8_t rnd[YSM_MAX_PKT_SIZE - 1];  // Random data
        # } YHSM_RANDOM_GENERATE_RESP;
        num_bytes = ord(data[0])
        if num_bytes != self.num_bytes:
            raise exception.YHSM_Error("Incorrect number of bytes in response (got %s, expected %s)" \
                                           % (num_bytes, self.num_bytes))
        return data[1:1 + num_bytes]


class YHSM_Cmd_Random_Reseed(YHSM_Cmd):
    """
    Provide YubiHSM DRBG_CTR with a new seed.
    """
    def __init__(self, stick, seed):
        if type(seed) is not str:
            raise exception.YHSM_WrongInputType( \
                'seed', type(32), type(seed))
        if len(seed) != defines.CTR_DRBG_SEED_SIZE:
            raise exception.YHSM_WrongInputSize(
                'seed', defines.CTR_DRBG_SEED_SIZE, len(seed))
        # #define CTR_DRBG_SEED_SIZE      32
        # typedef struct {
        #   uint8_t seed[CTR_DRBG_SEED_SIZE];   // New seed
        # } YSM_RANDOM_RESEED_REQ;
        fmt = "%is" % (defines.CTR_DRBG_SEED_SIZE)
        packed = struct.pack(fmt, seed)
        YHSM_Cmd.__init__(self, stick, defines.YSM_RANDOM_RESEED, packed)

    def parse_result(self, data):
        # typedef struct {
        #   YSM_STATUS status;                  // Status
        # } YSM_RANDOM_RESEED_RESP;
        fmt = "B"
        self.status, = struct.unpack(fmt, data)
        if self.status == defines.YSM_STATUS_OK:
            return True
        else:
            raise exception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)


class YHSM_Cmd_Nonce_Get(YHSM_Cmd):
    """
    Get nonce value from YubiHSM - causes it to increment by one (or a specified number).
    """
    def __init__(self, stick, increment):
        if type(increment) is not int:
            raise exception.YHSM_WrongInputType( \
                'increment', type(1), type(increment))
        # typedef struct {
        #   uint16_t increment;                 // Size of increment to next nonce
        # } YSM_NONCE_GET_REQ;
        packed = struct.pack("<H", increment)
        YHSM_Cmd.__init__(self, stick, defines.YSM_NONCE_GET, packed)

    def parse_result(self, data):
        # typedef struct {
        #   YSM_STATUS status;                  // Status
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce
        # } YSM_NONCE_GET_RESP;
        fmt = "B %is" % (defines.YSM_AEAD_NONCE_SIZE)
        self.status, nonce = struct.unpack(fmt, data)
        if self.status == defines.YSM_STATUS_OK:
            self.response = YHSM_NonceResponse(nonce)
            return self.response
        else:
            raise exception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)


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
