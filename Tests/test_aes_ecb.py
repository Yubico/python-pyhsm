# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import sys
import unittest
import pyhsm

import test_common

class TestOtpValidate(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)
        # Enabled flags 0000e000 = YHSM_ECB_BLOCK_ENCRYPT,YHSM_ECB_BLOCK_DECRYPT,YHSM_ECB_BLOCK_DECRYPT_CMP
        self.kh_encrypt = 0x1001
        self.kh_decrypt = 0x1001
        self.kh_compare = 0x1001

    def test_aes_ecb_cmd_class(self):
        """ Test YHSM_Cmd_AES_ECB class. """
        this = pyhsm.aes_ecb_cmd.YHSM_Cmd_AES_ECB(None, None, '')
        # test repr method
        self.assertEquals(str, type(str(this)))
        this.executed = True
        self.assertEquals(str, type(str(this)))

    def test_encrypt_decrypt(self):
        """ Test to AES ECB decrypt something encrypted. """
        plaintext = 'Fjaellen 2011'.ljust(pyhsm.defines.YSM_BLOCK_SIZE)	# pad for compare after decrypt

        ciphertext = self.hsm.aes_ecb_encrypt(self.kh_encrypt, plaintext)

        self.assertNotEqual(plaintext, ciphertext)

        decrypted = self.hsm.aes_ecb_decrypt(self.kh_decrypt, ciphertext)

        self.assertEqual(plaintext, decrypted)

    def test_compare(self):
        """ Test to AES ECB decrypt and then compare something. """
        plaintext = 'Maverick'.ljust(pyhsm.defines.YSM_BLOCK_SIZE)

        ciphertext = self.hsm.aes_ecb_encrypt(self.kh_encrypt, plaintext)

        self.assertTrue(self.hsm.aes_ecb_compare(self.kh_compare, ciphertext, plaintext))
        self.assertFalse(self.hsm.aes_ecb_compare(self.kh_compare, ciphertext, plaintext[:-1] + 'x'))

    def test_compare_bad(self):
        """ Test AES decrypt compare with incorrect plaintext. """
        plaintext = 'Maverick'.ljust(pyhsm.defines.YSM_BLOCK_SIZE)

        ciphertext = self.hsm.aes_ecb_encrypt(self.kh_encrypt, plaintext)

        self.assertFalse(self.hsm.aes_ecb_compare(self.kh_compare, ciphertext, plaintext[:-1] + 'x'))

    def test_who_can_encrypt(self):
        """ Test what key handles can encrypt AES ECB encrypted blocks. """
        # Enabled flags 00002000 = YSM_AES_ECB_BLOCK_ENCRYPT
        # 0000000e - stored ok
        kh_enc = 0x0e

        plaintext = 'sommar'

        this = lambda kh: self.hsm.aes_ecb_encrypt(kh, plaintext)
        self.who_can(this, expected = [kh_enc])

    def test_who_can_decrypt(self):
        """ Test what key handles can decrypt AES ECB encrypted blocks. """
        # Enabled flags 00002000 = YSM_AES_ECB_BLOCK_ENCRYPT
        # 0000000e - stored ok
        kh_enc = 0x0e

        # Enabled flags 00004000 = YSM_AES_ECB_BLOCK_DECRYPT
        # 0000000f - stored ok
        kh_dec = 0x0f

        plaintext = 'sommar'
        ciphertext = self.hsm.aes_ecb_encrypt(kh_enc, plaintext)

        this = lambda kh: self.hsm.aes_ecb_decrypt(kh, ciphertext)
        self.who_can(this, expected = [kh_dec])

    def test_who_can_compare(self):
        """ Test what key handles can decrypt_compare AES ECB encrypted blocks. """
        # Enabled flags 00002000 = YSM_AES_ECB_BLOCK_ENCRYPT
        # 0000000e - stored ok
        kh_enc = 0x0e

        # Enabled flags 00008000 = YSM_AES_ECB_BLOCK_DECRYPT_CMP
        # 00000010 - stored ok
        kh_cmp = 0x10

        # Decrypt implies decrypt_cmp
        #
        # Enabled flags 00004000 = YSM_AES_ECB_BLOCK_DECRYPT
        # 0000000f - stored ok
        kh_dec = 0x0f

        plaintext = 'sommar'
        ciphertext = self.hsm.aes_ecb_encrypt(kh_enc, plaintext)

        this = lambda kh: self.hsm.aes_ecb_decrypt(kh, ciphertext)
        self.who_can(this, expected = [kh_cmp, kh_dec])

    def test_aes_with_keystore_locked(self):
        """ Test AES with locking and then unlocking keystore. """
        if self.hsm.version.ver <= (0, 9, 8,):
            print ("Test for known bug in 0.9.8 disabled.")
            return None
        cleartext = "reference"
        res_before = self.hsm.aes_ecb_encrypt(0x2000, cleartext)
        # lock key store
        try:
            res = self.hsm.key_storage_unlock("A" * 8)
            self.fail("Expected YSM_MISMATCH/YSM_KEY_STORAGE_LOCKED, got %s" % (res))
        except pyhsm.exception.YHSM_CommandFailed, e:
            if self.hsm.version.have_key_store_decrypt():
                self.assertEquals(e.status, pyhsm.defines.YSM_MISMATCH)
            else:
                self.assertEquals(e.status, pyhsm.defines.YSM_KEY_STORAGE_LOCKED)
        # make sure we can't AES encrypt when keystore is locked
        try:
            res = self.hsm.aes_ecb_encrypt(0x2000, cleartext)
            self.fail("Expected YSM_KEY_STORAGE_LOCKED, got %s (before lock: %s)" \
                          % (res.encode("hex"), res_before.encode("hex")))
        except pyhsm.exception.YHSM_CommandFailed, e:
            self.assertEquals(e.status, pyhsm.defines.YSM_KEY_STORAGE_LOCKED)
        # unlock key store with correct passphrase
        self.assertTrue(self.hsm.key_storage_unlock(test_common.HsmPassphrase.decode("hex")))
        # make sure it is properly unlocked
        res_after = self.hsm.aes_ecb_encrypt(0x2000, cleartext)
        self.assertEquals(res_before, res_after)
