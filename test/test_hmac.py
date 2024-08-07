# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import sys
import unittest
import pyhsm

from . import test_common

class TestHMACSHA1(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)
        # Enabled flags 00010000 = YSM_HMAC_SHA1_GENERATE
        # 00003031 - stored ok
        self.kh = 0x3031

    def test_nist_test_vector(self):
        """ Test HMAC SHA1 with NIST PUB 198 A.2 test vector. """
        data = b'Sample #2'

        this = self.hsm.hmac_sha1(self.kh, data).execute()
        self.assertEqual(this.get_hash(), bytes.fromhex('0922d3405faa3d194f82a45830737d5cc6c75d24'))

        # test of repr method
        self.assertEqual(str, type(str(this)))

    def test_hmac_numeric_flags(self):
        """ Test HMAC SHA1 with numeric flags. """
        data = b'Sample #2'

        flags = pyhsm.defines.YSM_HMAC_SHA1_RESET | pyhsm.defines.YSM_HMAC_SHA1_FINAL
        this = self.hsm.hmac_sha1(self.kh, data, flags = flags).execute()
        self.assertEqual(this.get_hash(), bytes.fromhex('0922d3405faa3d194f82a45830737d5cc6c75d24'))

    def test_hmac_continuation(self):
        """ Test HMAC continuation. """
        data = b'Sample #2'

        this = self.hsm.hmac_sha1(self.kh, data[:3], final = False)
        self.assertEqual(this.get_hash(), '\x00' * 20)
        this.next(data[3:], final = True).execute()
        self.assertEqual(this.get_hash(), bytes.fromhex('0922d3405faa3d194f82a45830737d5cc6c75d24'))

    def test_hmac_continuation2(self):
        """ Test HMAC nasty continuation. """
        data = b'Sample #2'

        this = self.hsm.hmac_sha1(self.kh, b'', final = False)
        self.assertEqual(this.get_hash(), '\x00' * 20)
        this.next(data[:3], final = False).execute()
        this.next(data[3:], final = False).execute()
        this.next(b'', final = True).execute()
        self.assertEqual(this.get_hash(), bytes.fromhex('0922d3405faa3d194f82a45830737d5cc6c75d24'))

    def test_hmac_interrupted(self):
        """ Test interrupted HMAC. """
        data = b'Sample #2'

        this = self.hsm.hmac_sha1(self.kh, data[:3], final = False)
        self.assertEqual(this.get_hash(), '\x00' * 20)
        self.assertTrue(self.hsm.echo(b'hmac unit test'))
        this.next(data[3:], final = True).execute()
        self.assertEqual(this.get_hash(), bytes.fromhex('0922d3405faa3d194f82a45830737d5cc6c75d24'))

    def test_hmac_interrupted2(self):
        """ Test AES-interrupted HMAC. """
        data = b'Sample #2'
        plaintext = b'Maverick'.ljust(pyhsm.defines.YSM_BLOCK_SIZE)
        kh_encrypt = 0x1001
        kh_decrypt = 0x1001

        this = self.hsm.hmac_sha1(self.kh, data[:3], final = False)
        self.assertEqual(this.get_hash(), '\x00' * 20)
        # AES encrypt-decrypt in the middle of HMAC calculation
        ciphertext = self.hsm.aes_ecb_encrypt(kh_encrypt, plaintext)
        self.assertNotEqual(plaintext, ciphertext)
        decrypted = self.hsm.aes_ecb_decrypt(kh_decrypt, ciphertext)
        self.assertEqual(plaintext, decrypted)
        # continue HMAC
        this.next(data[3:], final = True).execute()
        self.assertEqual(this.get_hash(), bytes.fromhex('0922d3405faa3d194f82a45830737d5cc6c75d24'))

    def test_hmac_wrong_key_handle(self):
        """ Test HMAC SHA1 operation with wrong key handle. """
        try:
            res = self.hsm.hmac_sha1(0x01, b'foo').execute()
            self.fail("Expected YSM_FUNCTION_DISABLED, got %s" % (res))
        except pyhsm.exception.YHSM_CommandFailed as e:
            self.assertEqual(e.status, pyhsm.defines.YSM_FUNCTION_DISABLED)

    def test_who_can_hash(self):
        """ Test what key handles can create HMAC SHA1 hashes. """
        # Enabled flags 00010000 = YSM_HMAC_SHA1_GENERATE
        # 00000011 - stored ok
        data = b'Sample #2'

        this = lambda kh: self.hsm.hmac_sha1(kh, data).execute()
        self.who_can(this, expected = [0x11])

    def test_generated_sha1_class(self):
        """ Test YHSM_GeneratedHMACSHA1 class. """
        this = pyhsm.hmac_cmd.YHSM_GeneratedHMACSHA1(0x0, 'a' * 20, True)
        # test repr method
        self.assertEqual(str, type(str(this)))

    def test_sha1_to_buffer(self):
        """ Test HMAC SHA1 to internal buffer. """
        self.assertEqual(0, self.hsm.load_random(0, offset = 0)) # offset = 0 clears buffer

        self.hsm.hmac_sha1(self.kh, b'testing is fun!', to_buffer = True)
        # Verify there is now 20 bytes in the buffer
        self.assertEqual(pyhsm.defines.YSM_SHA1_HASH_SIZE, self.hsm.load_random(0, offset = 1))

    def test_hmac_continuation_with_buffer(self):
        """ Test HMAC continuation with buffer. """
        data = b'Sample #2'

        self.assertEqual(0, self.hsm.load_random(0, offset = 0)) # offset = 0 clears buffer
        self.assertEqual(0, self.hsm.load_random(0, offset = 1))

        this = self.hsm.hmac_sha1(self.kh, b'', final = False)
        self.assertEqual(this.get_hash(), '\x00' * 20)
        this.next(data[:3], final = False).execute()
        this.next(data[3:], final = False).execute()
        this.next(b'', final = True, to_buffer = True).execute()
        # Verify there is now 20 bytes in the buffer
        self.assertEqual(pyhsm.defines.YSM_SHA1_HASH_SIZE, self.hsm.load_random(0, offset = 1))
