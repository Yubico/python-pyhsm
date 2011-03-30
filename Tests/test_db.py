# Copyright (c) 2011, Yubico AB
# All rights reserved.

import os
import sys
import unittest
import pyhsm

import test_common

from test_yubikey_validate import YubiKeyEmu

class TestInternalDB(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)
        self.key = "A" * 16
        self.uid = 'f0f1f2f3f4f5'.decode('hex')
        self.public_id = '4d4d4d4d4d4d'.decode('hex')

    def test_store_yubikey(self):
        """ Test storing a YubiKey in the internal database. """
        # Key handle 0x2000 has all flags enabled
        key_handle = 0x2000

        secret = pyhsm.secrets_cmd.YHSM_YubiKeySecret(self.key, self.uid)
        self.hsm.load_secret(secret)

        aead = self.hsm.generate_aead(self.public_id, key_handle)

        # Try to store a record. YSM_ID_DUPLICATE is not an error since we don't
        # always zap the configuration before running the test suite.
        try:
            self.assertTrue(self.hsm.db_store_yubikey(self.public_id, key_handle, aead))
        except pyhsm.exception.YHSM_CommandFailed, e:
            self.assertEqual(e.status, pyhsm.defines.YSM_ID_DUPLICATE)

    def test_db_validate_yubikey_otp(self):
        """ Test bad OTP validation for key in internal database. """
        try:
            res = self.hsm.db_validate_yubikey_otp(self.public_id, "x" * 16)
            self.fail("Expected YSM_OTP_INVALID, got %s" % (res))
        except pyhsm.exception.YHSM_CommandFailed, e:
            self.assertEqual(e.status, pyhsm.defines.YSM_OTP_INVALID)

    def test_real_validate(self):
        """ Test real validation of YubiKey OTP against internal database. """
        # Key handle 0x2000 has all flags enabled
        key_handle = 0x2000

        # randomize last byte of public_id to not have to try so hard to
        # find an unused OTP ;)
        this_public_id = self.public_id[:-1] + os.urandom(1)

        secret = pyhsm.secrets_cmd.YHSM_YubiKeySecret(self.key, self.uid)
        self.hsm.load_secret(secret)

        aead = self.hsm.generate_aead(this_public_id, key_handle)

        # Try to store a record. YSM_ID_DUPLICATE is not a duplicate since we don't
        # always zap the configuration before running the test suite.
        try:
            self.assertTrue(self.hsm.db_store_yubikey(this_public_id, key_handle, aead))
        except pyhsm.exception.YHSM_CommandFailed, e:
            self.assertEqual(e.status, pyhsm.defines.YSM_ID_DUPLICATE)

        # OK, now we know there is an entry for this_public_id in the database -
        session_ctr = 1	# the 16 bit power-up counter of the YubiKey
        use_ctr = 1
        while session_ctr < 0xffff:
            timestamp = 0xffff # dunno
            YK = YubiKeyEmu(self.uid, session_ctr, timestamp, use_ctr)
            otp = YK.get_otp(self.key)
            try:
                res = self.hsm.db_validate_yubikey_otp(this_public_id, otp)
                self.assertTrue(isinstance(res, pyhsm.validate_cmd.YHSM_ValidationResult))
                self.assertEqual(res.public_id, this_public_id)
                self.assertEqual(res.session_ctr, session_ctr)
            except pyhsm.exception.YHSM_CommandFailed, e:
                if e.status != pyhsm.defines.YSM_OTP_REPLAY:
                    raise
            # don't bother with use_ctr - test run 5 would mean we first have to
            # exhaust 4 * 256 use_ctr increases before the YubiHSM would pass our OTP
            session_ctr += 1
