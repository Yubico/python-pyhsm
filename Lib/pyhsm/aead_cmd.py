"""
implementations of AEAD commands for the YubiHSM
"""

# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_AEAD_Random_Generate'
    'YHSM_Cmd_AEAD_Buffer_Generate',
    'YHSM_Cmd_AEAD_Decrypt_Cmp',
    'YHSM_GeneratedAEAD'
]

from cmd import YHSM_Cmd
import exception
import secrets_cmd

class YHSM_AEAD_Cmd(YHSM_Cmd):
    """
    Class for common non-trivial parse_result for commands returning a
    YSM_AEAD_GENERATE_RESP.
    """
    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: nonce=%s, key_handle=0x%x, status=%s>' % (
                self.__class__.__name__,
                hex(id(self)),
                self.nonce.encode('hex'),
                self.key_handle,
                defines.status2str(self.status)
                )
        else:
            return '<%s instance at %s (not executed)>' % (
                self.__class__.__name__,
                hex(id(self))
                )

    def parse_result(self, data):
        """
        Returns a YHSM_GeneratedAEAD instance, or throws exception.YHSM_CommandFailed.
        """
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Status
        #   uint8_t numBytes;                   // Number of bytes in AEAD block
        #   uint8_t aead[YSM_AEAD_MAX_SIZE];    // AEAD block
        # } YSM_AEAD_GENERATE_RESP;

        nonce, \
            key_handle, \
            self.status, \
            num_bytes = struct.unpack_from("< %is I B B" % (defines.YSM_AEAD_NONCE_SIZE), data, 0)
        if self.status == defines.YSM_STATUS_OK:
            # struct.hash is not always of size SHA1_HASH_SIZE,
            # it is really the size of numBytes
            offset = defines.YSM_AEAD_NONCE_SIZE + 6
            aead = data[offset:offset + num_bytes]
            self.response = YHSM_GeneratedAEAD(nonce, key_handle, aead)
            return self.response
        else:
            raise exception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)

class YHSM_Cmd_AEAD_Generate(YHSM_AEAD_Cmd):
    """
    Generate AEAD block from data for a specific key.

    `data' is either a string, or a YHSM_YubiKeySecret.
    """
    def __init__(self, stick, nonce, key_handle, data):
        if type(nonce) is not str:
            raise exception.YHSM_WrongInputType( \
                'nonce', type(''), type(nonce))
        if type(key_handle) is not int:
            raise exception.YHSM_WrongInputType( \
                'key_handle', type(1), type(key_handle))
        if isinstance(data, secrets_cmd.YHSM_YubiKeySecret):
            data = data.pack()
        if type(data) is not str:
            raise exception.YHSM_WrongInputType( \
                'data', type(''), type(data))
        self.data = data
        self.nonce = nonce
        self.key_handle = key_handle
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t numBytes;                   // Number of data bytes
        #   uint8_t data[YSM_DATA_BUF_SIZE];    // Data
        # } YSM_AEAD_GENERATE_REQ;
        fmt = "< %is I B %is" % (defines.YSM_AEAD_NONCE_SIZE, len(self.data))
        packed = struct.pack(fmt, nonce, key_handle, len(self.data), self.data)
        YHSM_Cmd.__init__(self, stick, defines.YSM_AEAD_GENERATE, packed)

class YHSM_Cmd_AEAD_Random_Generate(YHSM_AEAD_Cmd):
    """
    Generate a random AEAD block using the YubiHSM internal TRNG.

    To generate a secret for a YubiKey, use public_id as nonce.
    """
    def __init__(self, stick, nonce, key_handle, num_bytes):
        if type(nonce) is not str:
            raise exception.YHSM_WrongInputType( \
                'nonce', type(''), type(nonce))
        if type(key_handle) is not int:
            raise exception.YHSM_WrongInputType( \
                'key_handle', type(1), type(key_handle))
        if type(num_bytes) is not int:
            raise exception.YHSM_WrongInputType( \
                'num_bytes', type(1), type(num_bytes))
        self.nonce = nonce
        self.key_handle = key_handle
        self.num_bytes = num_bytes
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t numBytes;                   // Number of bytes to randomize
        # } YSM_RANDOM_AEAD_GENERATE_REQ;
        fmt = "< %is I B" % (defines.YSM_AEAD_NONCE_SIZE)
        packed = struct.pack(fmt, nonce, key_handle, num_bytes)
        YHSM_Cmd.__init__(self, stick, defines.YSM_RANDOM_AEAD_GENERATE, packed)

class YHSM_Cmd_AEAD_Buffer_Generate(YHSM_AEAD_Cmd):
    """
    Generate AEAD block of data buffer for a specific key.

    After a key has been loaded into the internal data buffer, this command can be
    used a number of times to get AEADs of the data buffer for different key handles.

    For example, to encrypt a YubiKey secrets to one or more Yubico KSM's that
    all have a YubiHSM attached to them.
    """
    def __init__(self, stick, nonce, key_handle):
        self.nonce = nonce
        self.key_handle = key_handle
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        # } YSM_BUFFER_AEAD_GENERATE_REQ;
        packed = struct.pack("< %is I" % (defines.YSM_AEAD_NONCE_SIZE), \
                                 self.nonce, self.key_handle)
        YHSM_Cmd.__init__(self, stick, defines.YSM_BUFFER_AEAD_GENERATE, packed)

class YHSM_Cmd_AEAD_Decrypt_Cmp(YHSM_Cmd):
    """
    Validate an AEAD using the YubiHSM, optionally matching it against
    some known plain text. Matching is done inside the YubiHSM so the
    decrypted AEAD never leaves the YubiHSM.

    Empty cleartext just validates the AEAD.
    """
    def __init__(self, stick, nonce, key_handle, aead, cleartext=''):
        if type(cleartext) is not str:
            raise exception.YHSM_WrongInputType(
                'cleartext', type(''), type(cleartext))
        expected_ct_len = len(aead.data) - defines.YSM_AEAD_MAC_SIZE
        if len(cleartext) > expected_ct_len:
            raise exception.YHSM_Error("Cleartext too long for supplied AEAD (%i > %i)" \
                                           % (len(cleartext), expected_ct_len))
        if len(cleartext) < expected_ct_len:
            # must pad with zeros
            cleartext = cleartext.ljust(expected_ct_len, chr(0x0))
        data = cleartext + aead.data
        if len(data) > defines.YSM_MAX_PKT_SIZE - 10:
            raise exception.YHSM_InputTooLong(
                'packed_aead+cleartext', defines.YSM_MAX_PKT_SIZE - 10, len(data))
        if type(nonce) is not str:
            raise exception.YHSM_WrongInputType(
                'nonce', type(''), type(nonce))
        if type(key_handle) is not int:
            raise exception.YHSM_WrongInputType(
                'key_handle', type(1), type(key_handle))

        # store padded for comparision in parse_result
        self.nonce = nonce.ljust(defines.YSM_AEAD_NONCE_SIZE, chr(0x0))
        self.key_handle = key_handle
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t numBytes;                   // Number of data bytes (cleartext + aead)
        #   uint8_t data[YSM_MAX_PKT_SIZE - 0x10]; // Data (cleartext + aead). Empty cleartext validates aead only
        # } YSM_AEAD_DECRYPT_CMP_REQ;
        fmt = "< %is I B %is" % (defines.YSM_AEAD_NONCE_SIZE, len(data))
        packed = struct.pack(fmt, self.nonce, key_handle, len(data), data)
        YHSM_Cmd.__init__(self, stick, defines.YSM_AEAD_DECRYPT_CMP, packed)

    def parse_result(self, data):
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Status
        # } YSM_AEAD_DECRYPT_CMP_RESP;
        fmt = "< %is I B" % (defines.YSM_AEAD_NONCE_SIZE)
        nonce, key_handle, self.status = struct.unpack(fmt, data)
        if nonce != self.nonce:
            raise exception.YHSM_Error("Incorrect nonce in response (got %s, expected %s)" \
                                                 % (nonce.encode('hex'), self.nonce.encode('hex')))
        if key_handle != self.key_handle:
            raise exception.YHSM_Error("Incorrect key_handle in response (got 0x%x, expected 0x%x)" \
                                                 % (key_handle, self.key_handle))
        if self.status == defines.YSM_STATUS_OK:
            return True
        if self.status == defines.YSM_MISMATCH:
            return False
        else:
            raise exception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)

class YHSM_GeneratedAEAD():
    """ Small class to represent a YHSM_AEAD_GENERATE_RESP. """
    def __init__(self, nonce, key_handle, aead):
        self.nonce = nonce
        self.key_handle = key_handle
        self.data = aead

    def __repr__(self):
        return '<%s instance at %s: nonce=%s, key_handle=0x%x, data=%i bytes>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.nonce.encode('hex'),
            self.key_handle,
            len(self.data)
            )

    def save(self, filename):
        """ Store AEAD in a file. """
        f = open(filename, "w")
        f.write(self.data)
        f.close()

    def load(self, filename):
        """ Load AEAD from a file. """
        f = open(filename, "r")
        self.data = f.read(defines.YSM_MAX_KEY_SIZE + defines.YSM_BLOCK_SIZE)
        f.close()
