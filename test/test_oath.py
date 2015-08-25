# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct
import unittest
import pyhsm
import pyhsm.oath_hotp

import test_common

class TestOath(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)

        key = "3132333435363738393031323334353637383930".decode('hex')
	# Enabled flags 00010000 = YSM_HMAC_SHA1_GENERATE
        flags = struct.pack("< I", 0x10000)
        self.nonce = 'f1f2f3f4f5f6'.decode('hex')
        # key 0x2000 has all flags set
        self.key_handle = 0x2000
        self.phantom = pyhsm.defines.YSM_TEMP_KEY_HANDLE

        self.hsm.load_secret(key + flags)
        self.aead = self.hsm.generate_aead(self.nonce, self.key_handle)

        self.assertTrue(isinstance(self.aead, pyhsm.aead_cmd.YHSM_GeneratedAEAD))

        # Load the AEAD into the phantom key handle 0xffffffff.
        self.assertTrue(self.hsm.load_temp_key(self.nonce, self.key_handle, self.aead))

    def test_OATH_HOTP_values(self):
        """ Test OATH HOTP known results. """
        test_vectors = [(0, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", 755224,),
                        (1, "75a48a19d4cbe100644e8ac1397eea747a2d33ab", 287082,),
                        (2, "0bacb7fa082fef30782211938bc1c5e70416ff44", 359152,),
                        (3, "66c28227d03a2d5529262ff016a1e6ef76557ece", 969429,),
                        (4, "a904c900a64b35909874b33e61c5938a8e15ed1c", 338314,),
                        (5, "a37e783d7b7233c083d4f62926c7a25f238d0316", 254676,),
                        (6, "bc9cd28561042c83f219324d3c607256c03272ae", 287922,),
                        (7, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", 162583,),
                        (8, "1b3c89f65e6c9e883012052823443f048b4332db", 399871,),
                        (9, "1637409809a679dc698207310c8c7fc07290d9e5", 520489,),
                        (30, "543c61f8f9aeb35f6dbc3a6847c3fe288cc0ee4c", 26920,),
                        ]

        for c, expected, code in test_vectors:
            hmac_result = self.hsm.hmac_sha1(self.phantom, struct.pack("> Q", c)).get_hash()
            self.assertEqual(expected, hmac_result.encode('hex'))
            self.assertEqual(code, pyhsm.oath_hotp.truncate(hmac_result, length=6))

    def test_OATH_HOTP_validation(self):
        """ Test complete OATH HOTP code validation. """

        oath = lambda counter, user_code, look_ahead: \
            pyhsm.oath_hotp.search_for_oath_code(self.hsm, self.key_handle, self.nonce, self.aead, \
                                                     counter, user_code, look_ahead)

        self.assertEqual(1,	oath(0, 755224, 1))
        self.assertEqual(4,	oath(0, 969429, 4))
        self.assertEqual(None,	oath(0, 969429, 3))
        self.assertEqual(10,	oath(9, 520489, 3))
        self.assertEqual(31,    oath(30, 26920, 1))
