# Copyright (c) 2012 Yubico AB
# See the file COPYING for licence statement.

import sys
import unittest
import pyhsm

from . import test_common

class TestSoftHSM(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)
        self.nonce = bytes.fromhex("4d4d4d4d4d4d")
        self.key = b"A" * 16

    def test_aes_CCM_encrypt_decrypt(self):
        """ Test decrypting encrypted data. """
        key = bytes([0x09] * 16)
        key_handle = 1
        plaintext = b"foo".ljust(16, b'\x00')
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        pt = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, ct, decrypt = True)
        self.assertEqual(plaintext, pt)

    def test_aes_CCM_wrong_key(self):
        """ Test decrypting encrypted data with wrong key. """
        key = bytes([0x09] * 16)
        key_handle = 1
        plaintext = b"foo".ljust(16, b'\x00')
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        key = bytes([0x08] * 16)
        self.assertRaises(pyhsm.exception.YHSM_Error, pyhsm.soft_hsm.aesCCM,
                          key, key_handle, self.nonce, ct, decrypt = True)

    def test_aes_CCM_wrong_key_handle(self):
        """ Test decrypting encrypted data with wrong key_handle. """
        key = bytes([0x09] * 16)
        key_handle = 1
        plaintext = b"foo".ljust(16, b'\x00')
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        key_handle = 2
        self.assertRaises(pyhsm.exception.YHSM_Error, pyhsm.soft_hsm.aesCCM,
                          key, key_handle, self.nonce, ct, decrypt = True)

    def test_soft_simple_aead_generation(self):
        """ Test soft_hsm simple AEAD generation. """
        key_handle = 0x2000
        plaintext = b'foo'.ljust(16, b'\x00')
        key = bytes.fromhex("2000" * 16)
        # generate soft AEAD
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        # generate hard AEAD
        aead = self.hsm.generate_aead_simple(self.nonce, key_handle, plaintext)

        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        self.assertEqual(aead.data, ct)

        # decrypt the AEAD again
        pt = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, ct, decrypt = True)
        self.assertEqual(plaintext, pt)

    def test_soft_generate_long_aead(self):
        """ Test soft_hsm generation of long AEAD. """
        key_handle = 0x2000
        plaintext = b'A' * 64
        key = bytes.fromhex("2000" * 16)
        # generate soft AEAD
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        # generate hard AEAD
        aead = self.hsm.generate_aead_simple(self.nonce, key_handle, plaintext)

        self.assertEqual(aead.data, ct)

        # decrypt the AEAD again
        pt = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, ct, decrypt = True)
        self.assertEqual(plaintext, pt)

    def test_soft_generate_yubikey_secrets_aead(self):
        """ Test soft_hsm generation of YubiKey secrets AEAD. """
        key_handle = 0x2000
        plaintext = b'A' * 22
        key = bytes.fromhex("2000" * 16)
        # generate soft AEAD
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        # generate hard AEAD
        aead = self.hsm.generate_aead_simple(self.nonce, key_handle, plaintext)

        self.assertEqual(aead.data, ct)

        # decrypt the AEAD again
        pt = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, ct, decrypt = True)
        self.assertEqual(plaintext, pt)
