# Copyright (c) 2012 Yubico AB
# See the file COPYING for licence statement.

import sys
import unittest
import pyhsm

import test_common

class TestSoftHSM(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)
        self.nonce = "4d4d4d4d4d4d".decode('hex')
        self.key = "A" * 16

    def test_aes_CCM_encrypt_decrypt(self):
        """ Test decrypting encrypted data. """
        key = chr(0x09) * 16
        key_handle = 1
        plaintext = "foo".ljust(16, chr(0x0))
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        pt = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, ct, decrypt = True)
        self.assertEquals(plaintext, pt)

    def test_aes_CCM_wrong_key(self):
        """ Test decrypting encrypted data with wrong key. """
        key = chr(0x09) * 16
        key_handle = 1
        plaintext = "foo".ljust(16, chr(0x0))
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        key = chr(0x08) * 16
        self.assertRaises(pyhsm.exception.YHSM_Error, pyhsm.soft_hsm.aesCCM,
                          key, key_handle, self.nonce, ct, decrypt = True)

    def test_aes_CCM_wrong_key_handle(self):
        """ Test decrypting encrypted data with wrong key_handle. """
        key = chr(0x09) * 16
        key_handle = 1
        plaintext = "foo".ljust(16, chr(0x0))
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        key_handle = 2
        self.assertRaises(pyhsm.exception.YHSM_Error, pyhsm.soft_hsm.aesCCM,
                          key, key_handle, self.nonce, ct, decrypt = True)

    def test_soft_simple_aead_generation(self):
        """ Test soft_hsm simple AEAD generation. """
        key_handle = 0x2000
        plaintext = 'foo'.ljust(16, chr(0x0))
        key = str("2000" * 16).decode('hex')
        # generate soft AEAD
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        # generate hard AEAD
        aead = self.hsm.generate_aead_simple(self.nonce, key_handle, plaintext)

        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        self.assertEquals(aead.data, ct)

        # decrypt the AEAD again
        pt = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, ct, decrypt = True)
        self.assertEquals(plaintext, pt)

    def test_soft_generate_long_aead(self):
        """ Test soft_hsm generation of long AEAD. """
        key_handle = 0x2000
        plaintext = 'A' * 64
        key = str("2000" * 16).decode('hex')
        # generate soft AEAD
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        # generate hard AEAD
        aead = self.hsm.generate_aead_simple(self.nonce, key_handle, plaintext)

        self.assertEquals(aead.data, ct)

        # decrypt the AEAD again
        pt = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, ct, decrypt = True)
        self.assertEquals(plaintext, pt)

    def test_soft_generate_yubikey_secrets_aead(self):
        """ Test soft_hsm generation of YubiKey secrets AEAD. """
        key_handle = 0x2000
        plaintext = 'A' * 22
        key = str("2000" * 16).decode('hex')
        # generate soft AEAD
        ct = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, plaintext, decrypt = False)
        # generate hard AEAD
        aead = self.hsm.generate_aead_simple(self.nonce, key_handle, plaintext)

        self.assertEquals(aead.data, ct)

        # decrypt the AEAD again
        pt = pyhsm.soft_hsm.aesCCM(key, key_handle, self.nonce, ct, decrypt = True)
        self.assertEquals(plaintext, pt)
