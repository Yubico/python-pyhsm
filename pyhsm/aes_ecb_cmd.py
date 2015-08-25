"""
implementations of AES ECB block cipher commands to execute on a YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    # classes
    #'YHSM_Cmd_AES_ECB',
    'YHSM_Cmd_AES_ECB_Encrypt',
    'YHSM_Cmd_AES_ECB_Decrypt',
    'YHSM_Cmd_AES_ECB_Compare',
]

import pyhsm.defines
import pyhsm.exception
from pyhsm.cmd import YHSM_Cmd

class YHSM_Cmd_AES_ECB(YHSM_Cmd):
    """ Common code for command classes in this module. """
    status = None
    key_handle = 0x00

    def __init__(self, stick, command, payload):
        YHSM_Cmd.__init__(self, stick, command, payload)

    def __repr__(self):
        return '<%s instance at %s: key_handle=0x%x>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.key_handle
            )

    def parse_result(self, data):
        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   uint8_t ciphertext[YSM_BLOCK_SIZE];  // Ciphertext block
        #   YHSM_STATUS status;                  // Encryption status
        # } YHSM_ECB_BLOCK_ENCRYPT_RESP;

        # OR

        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   uint8_t plaintext[YSM_BLOCK_SIZE];   // Plaintext block
        #   YHSM_STATUS status;                  // Decryption status
        # } YHSM_ECB_BLOCK_DECRYPT_RESP;

        fmt = "< I %is B" % (pyhsm.defines.YSM_BLOCK_SIZE)

        key_handle, \
            result, \
            self.status = struct.unpack(fmt, data)

        # check that returned key_handle matches the one in the request
        pyhsm.util.validate_cmd_response_hex('key_handle', key_handle, self.key_handle)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            return result
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)


class YHSM_Cmd_AES_ECB_Encrypt(YHSM_Cmd_AES_ECB):
    """
    Have the YubiHSM AES ECB encrypt something using the key of a key handle.
    """
    def __init__(self, stick, key_handle, plaintext):
        pyhsm.util.input_validate_str(plaintext, name='plaintext', max_len = pyhsm.defines.YSM_BLOCK_SIZE)
        self.key_handle = pyhsm.util.input_validate_key_handle(key_handle)
        # typedef struct {
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t plaintext[YHSM_BLOCK_SIZE];  // Plaintext block
        # } YHSM_ECB_BLOCK_ENCRYPT_REQ;
        payload = struct.pack('<I', key_handle) + \
            plaintext.ljust(pyhsm.defines.YSM_BLOCK_SIZE, chr(0x0))
        YHSM_Cmd_AES_ECB.__init__(self, stick, pyhsm.defines.YSM_AES_ECB_BLOCK_ENCRYPT, payload)


class YHSM_Cmd_AES_ECB_Decrypt(YHSM_Cmd_AES_ECB):
    """
    Have the YubiHSM AES ECB decrypt something using the key of a key handle.
    """
    def __init__(self, stick, key_handle, ciphertext):
        self.key_handle = pyhsm.util.input_validate_key_handle(key_handle)
        pyhsm.util.input_validate_str(ciphertext, name='ciphertext', exact_len = pyhsm.defines.YSM_BLOCK_SIZE)
        # #define YHSM_BLOCK_SIZE          16    // Size of block operations
        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   uint8_t ciphertext[YHSM_BLOCK_SIZE]; // Ciphertext block
        # } YHSM_ECB_BLOCK_DECRYPT_REQ;
        fmt = "< I %is" % (pyhsm.defines.YSM_BLOCK_SIZE)
        payload = struct.pack(fmt, key_handle, ciphertext)
        YHSM_Cmd_AES_ECB.__init__(self, stick, pyhsm.defines.YSM_AES_ECB_BLOCK_DECRYPT, payload)


class YHSM_Cmd_AES_ECB_Compare(YHSM_Cmd_AES_ECB):
    """
    Have the YubiHSM AES ECB decrypt something using the key of a key handle, and
    then compare it with a plaintext we supply.

    Requires you to know the plaintext to verify if the ciphertext matches it,
    providing added security in some applications.
    """
    def __init__(self, stick, key_handle, ciphertext, plaintext):
        self.key_handle = pyhsm.util.input_validate_key_handle(key_handle)
        pyhsm.util.input_validate_str(ciphertext, name='ciphertext')
        pyhsm.util.input_validate_str(plaintext, name='plaintext')
        # #define YHSM_BLOCK_SIZE          16    // Size of block operations
        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   uint8_t ciphertext[YHSM_BLOCK_SIZE]; // Ciphertext block
        #   uint8_t plaintext[YHSM_BLOCK_SIZE];  // Plaintext block
        # } YHSM_ECB_BLOCK_DECRYPT_CMP_REQ;
        fmt = "< I %is %is" % (pyhsm.defines.YSM_BLOCK_SIZE, pyhsm.defines.YSM_BLOCK_SIZE)
        payload = struct.pack(fmt, key_handle, ciphertext, plaintext)
        YHSM_Cmd_AES_ECB.__init__(self, stick, pyhsm.defines.YSM_AES_ECB_BLOCK_DECRYPT_CMP, payload)

    def parse_result(self, data):
        # #define YHSM_BLOCK_SIZE          16    // Size of block operations
        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   YHSM_STATUS status;                  // Decryption + verification status
        # } YHSM_ECB_BLOCK_VERIFY_RESP;
        fmt = "< I B"
        key_handle, \
            self.status = struct.unpack(fmt, data)

        # check that returned key_handle matches the one in the request
        pyhsm.util.validate_cmd_response_hex('key_handle', key_handle, self.key_handle)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            return True
        if self.status == pyhsm.defines.YSM_MISMATCH:
            return False
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)
