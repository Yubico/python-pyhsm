# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import sys
import unittest
import pyhsm

import test_common

class TestOtpValidate(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)

    def test_load_secret_wrong_key(self):
        """ Test load_secret with key that should not be allowed to. """
        key = "A" * 16
        uid = '\x4d\x4d\x4d\x4d\x4d\x4d'
        public_id = 'f0f1f2f3f4f5'.decode('hex')
        # Enabled flags 00000100 = YHSM_AEAD_STORE
        # HSM> < keyload - Load key data now using flags 00000100. Press ESC to quit
        # 00000009 - stored ok
        key_handle = 9	# Enabled flags 00000020 = YHSM_AEAD_GENERATE

        secret = pyhsm.aead_cmd.YHSM_YubiKeySecret(key, uid)
        self.hsm.load_secret(secret)

        try:
            res = self.hsm.generate_aead(public_id, key_handle)
            self.fail("Expected YSM_FUNCTION_DISABLED, got %s" % (res))
        except pyhsm.exception.YHSM_CommandFailed, e:
            self.assertEquals(e.status, pyhsm.defines.YSM_FUNCTION_DISABLED)

    def test_load_secret(self):
        """ Test load_secret. """
        key = "A" * 16
        uid = '\x4d\x01\x4d\x02'
        public_id = 'f1f2f3f4f5f6'.decode('hex')
        if self.hsm.version.have_YSM_BUFFER_LOAD():
            # Enabled flags 60000004 = YSM_BUFFER_AEAD_GENERATE,YSM_USER_NONCE,YSM_BUFFER_LOAD
            # HSM (keys changed)> < keyload - Load key data now using flags 60000004. Press ESC to quit
            # 00001002 - stored ok
            key_handle = 0x1002
        else:
            # Enabled flags 00000004 = YSM_BUFFER_AEAD_GENERATE
            # HSM> < keyload - Load key data now using flags 00000004. Press ESC to quit
            # 00000003 - stored ok
            key_handle = 3

        secret = pyhsm.aead_cmd.YHSM_YubiKeySecret(key, uid)
        self.hsm.load_secret(secret)

        aead = self.hsm.generate_aead(public_id, key_handle)

        self.assertTrue(isinstance(aead, pyhsm.aead_cmd.YHSM_GeneratedAEAD))

        self.assertEqual(aead.nonce, public_id)
        self.assertEqual(aead.key_handle, key_handle)

    def test_yubikey_secrets(self):
        """ Test the class representing the YUBIKEY_SECRETS struct. """
        aes_128_key = 'a' * 16
        first = pyhsm.aead_cmd.YHSM_YubiKeySecret(aes_128_key, 'b')
        self.assertEqual(len(first.pack()), pyhsm.defines.KEY_SIZE + pyhsm.defines.UID_SIZE)
