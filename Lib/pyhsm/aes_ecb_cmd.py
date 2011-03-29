"""
implementations of AES ECB block cipher commands to execute on a YubiHSM
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_AES_ECB_Encrypt',
    'YHSM_Cmd_AES_ECB_Decrypt',
]

import exception
from cmd import YHSM_Cmd

class YHSM_Cmd_AES_ECB_Encrypt(YHSM_Cmd):
    """
    Have the YubiHSM AES ECB encrypt something using the key of a key handle.
    """
    def __init__(self, stick, key_handle, plaintext):
        if type(plaintext) is not str:
            raise exception.YHSM_WrongInputType(
                'plaintext', type(''), type(plaintext))
        self.key_handle = key_handle
        # typedef struct {
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t plaintext[YHSM_BLOCK_SIZE];  // Plaintext block
        # } YHSM_ECB_BLOCK_ENCRYPT_REQ;
        payload = struct.pack('<I', key_handle) + \
            plaintext.ljust(defines.YSM_BLOCK_SIZE, chr(0x0))
        YHSM_Cmd.__init__(self, stick, defines.YSM_ECB_BLOCK_ENCRYPT, payload)
        self.response_length = 22

    def __repr__(self):
        return '<%s instance at %s: key_handle=0x%x>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.key_handle
            )

    def parse_result(self, data):
        # #define YHSM_BLOCK_SIZE          16      // Size of block operations
        # typedef struct {
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t ciphertext[YHSM_BLOCK_SIZE]; // Ciphertext block
        #   YHSM_STATUS status;                  // Encryption status
        # } YHSM_ECB_BLOCK_ENCRYPT_RESP;
        key_handle, \
            self.ciphertext, \
            self.status = struct.unpack('<I16sB', data)
        if self.status == defines.YSM_STATUS_OK:
            return self.ciphertext
        else:
            raise exception.YHSM_CommandFailed('YHSM_ECB_BLOCK_ENCRYPT', self.status)


class YHSM_Cmd_AES_ECB_Decrypt(YHSM_Cmd):
    """
    Have the YubiHSM AES ECB decrypt something using the key of a key handle.
    """
    def __init__(self, stick, key_handle, ciphertext):
        if type(ciphertext) is not str:
            raise exception.YHSM_WrongInputType(
                'ciphertext', type(''), type(ciphertext))
        self.key_handle = key_handle
        # #define YHSM_BLOCK_SIZE          16    // Size of block operations
        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   uint8_t ciphertext[YHSM_BLOCK_SIZE]; // Ciphertext block
        # } YHSM_ECB_BLOCK_DECRYPT_REQ;
        payload = struct.pack('<I16s', key_handle, ciphertext)
        YHSM_Cmd.__init__(self, stick, defines.YSM_ECB_BLOCK_DECRYPT, payload)
        self.response_length = 22

    def __repr__(self):
        return '<%s instance at %s: key_handle=0x%x>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.key_handle
            )

    def parse_result(self, data):
        # #define YHSM_BLOCK_SIZE          16    // Size of block operations
        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   uint8_t plaintext[YHSM_BLOCK_SIZE];  // Plaintext block
        #   YHSM_STATUS status;                  // Decryption status
        # } YHSM_ECB_BLOCK_DECRYPT_RESP;
        key_handle, \
            plaintext, \
            self.status = struct.unpack('<I16sB', data)
        if self.status == defines.YSM_STATUS_OK:
            return plaintext
        else:
            raise exception.YHSM_CommandFailed('YHSM_ECB_BLOCK_DECRYPT', self.status)

class YHSM_Cmd_AES_ECB_Compare(YHSM_Cmd):
    """
    Have the YubiHSM AES ECB decrypt something using the key of a key handle, and
    then compare it with a plaintext we supply.

    Requires you to know the plaintext to verify if the ciphertext matches it,
    providing added security in some applications.
    """
    def __init__(self, stick, key_handle, ciphertext, plaintext):
        if type(ciphertext) is not str:
            raise exception.YHSM_WrongInputType(
                'ciphertext', type(''), type(ciphertext))
        if type(plaintext) is not str:
            raise exception.YHSM_WrongInputType(
                'plaintext', type(''), type(plaintext))
        self.key_handle = key_handle
        # #define YHSM_BLOCK_SIZE          16    // Size of block operations
        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   uint8_t ciphertext[YHSM_BLOCK_SIZE]; // Ciphertext block
        #   uint8_t plaintext[YHSM_BLOCK_SIZE];  // Plaintext block
        # } YHSM_ECB_BLOCK_DECRYPT_CMP_REQ;
        payload = struct.pack('<I', key_handle) + \
            ciphertext.ljust(defines.YSM_BLOCK_SIZE, chr(0x0)) + \
            plaintext.ljust(defines.YSM_BLOCK_SIZE, chr(0x0))
        YHSM_Cmd.__init__(self, stick, defines.YSM_ECB_BLOCK_DECRYPT_CMP, payload)
        self.response_length = 6

    def __repr__(self):
        return '<%s instance at %s: key_handle=0x%x>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.key_handle
            )

    def parse_result(self, data):
        # #define YHSM_BLOCK_SIZE          16    // Size of block operations
        # typedef struct {
        #   uint32_t keyHandle;                  // Key handle
        #   YHSM_STATUS status;                  // Decryption + verification status
        # } YHSM_ECB_BLOCK_VERIFY_RESP;
        key_handle, \
            self.status = struct.unpack('<IB', data)
        if self.status == defines.YSM_STATUS_OK:
            return True
        if self.status == defines.YSM_MISMATCH:
            return False
        else:
            raise exception.YHSM_CommandFailed('YHSM_ECB_BLOCK_DECRYPT_CMP', self.status)
