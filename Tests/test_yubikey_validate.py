# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import sys
import string
import unittest
import pyhsm

import test_common
from test_common import YubiKeyEmu, YubiKeyRnd

class TestYubikeyValidate(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)

        self.yk_key = 'F' * 16	# 128 bit AES key
        self.yk_uid = '\x4d\x01\x4d\x02\x4d\x4d'
        self.yk_rnd = YubiKeyRnd(self.yk_uid)
        self.yk_public_id = '4d4d4d4d4d4d'.decode('hex')

        secret = pyhsm.aead_cmd.YHSM_YubiKeySecret(self.yk_key, self.yk_uid)
        self.hsm.load_secret(secret)

        # YubiHSM includes key handle id in AES-CCM of aeads, so we must use same
        # key to generate and validate. Key 0x2000 has all flags.
        self.kh_generate = 0x2000
        self.kh_validate = 0x2000

        self.aead = self.hsm.generate_aead(self.yk_public_id, self.kh_generate)

    def test_validate_aead_cmp(self):
        """ Test that the AEAD generated contains our secrets. """
        secret = pyhsm.aead_cmd.YHSM_YubiKeySecret(self.yk_key, self.yk_uid)
        cleartext = secret.pack()
        self.assertTrue(self.hsm.validate_aead(self.yk_public_id, self.kh_validate, self.aead, cleartext))
        wrong_cleartext = 'X' + cleartext[1:]
        self.assertFalse(self.hsm.validate_aead(self.yk_public_id, self.kh_validate, self.aead, wrong_cleartext))

    def test_validate_aead_cmp_long(self):
        """ Test validating a long AEAD """
        cleartext = 'C' * 36
        key_handle = 0x2000 # key 0x2000 has all flags set
        nonce = '123456'
        aead = self.hsm.generate_aead_simple(nonce, key_handle, cleartext)
        self.assertTrue(self.hsm.validate_aead(nonce, key_handle, aead, cleartext))
        wrong_cleartext = 'X' + cleartext[1:]
        self.assertFalse(self.hsm.validate_aead(nonce, key_handle, aead, wrong_cleartext))

    def test_validate_yubikey(self):
        """ Test validate YubiKey OTP. """
        from_key = self.yk_rnd.from_key(self.yk_public_id, self.yk_key)
        self.assertTrue(pyhsm.yubikey.validate_yubikey_with_aead( \
                self.hsm, from_key, self.aead, self.kh_validate))

    def test_modhex_encode_decode(self):
        """ Test modhex encoding/decoding. """
        h = '4d014d024d4ddd5382b11195144da07d'
        self.assertEquals(h, pyhsm.yubikey.modhex_decode( pyhsm.yubikey.modhex_encode(h) ) )

    def test_split_id_otp(self):
        """ Test public_id + OTP split function. """
        public_id, otp, = pyhsm.yubikey.split_id_otp("ft" * 16)
        self.assertEqual(public_id, '')
        self.assertEqual(otp, "ft" * 16)

        public_id, otp, = pyhsm.yubikey.split_id_otp("cc" + "ft" * 16)
        self.assertEqual(public_id, 'cc')
        self.assertEqual(otp, "ft" * 16)
