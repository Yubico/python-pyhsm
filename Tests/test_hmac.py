# Copyright (c) 2011, Yubico AB
# All rights reserved.

import sys
import unittest
import pyhsm

import test_common

class TestHMACSHA1(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)
        # Enabled flags 00010000 = YSM_HMAC_SHA1_GENERATE
        # 00003031 - stored ok
        self.kh = 0x3031

    def test_nist_test_vector(self):
        """ Test HMAC SHA1 with NIST PUB 198 A.2 test vector. """
        data = 'Sample #2'

        res = self.hsm.hmac_sha1(self.kh, data).execute()
        self.assertEquals(res.hash_result.encode('hex'), '0922d3405faa3d194f82a45830737d5cc6c75d24')

    def test_hmac_continuation(self):
        """ Test HMAC continuation. """
        data = 'Sample #2'

        this = self.hsm.hmac_sha1(self.kh, data[:3], final = False)
        res = this.execute()
        self.assertEquals(res.hash_result.encode('hex'), '00' * 20)
        res = this.next(data[3:], final = True).execute()
        self.assertEquals(res.hash_result.encode('hex'), '0922d3405faa3d194f82a45830737d5cc6c75d24')

    def test_hmac_continuation2(self):
        """ Test HMAC nasty continuation. """
        data = 'Sample #2'

        this = self.hsm.hmac_sha1(self.kh, '', final = False)
        res = this.execute()
        self.assertEquals(res.hash_result.encode('hex'), '00' * 20)
        res = this.next(data[:3], final = False).execute()
        res = this.next(data[3:], final = False).execute()
        res = this.next('', final = True).execute()
        self.assertEquals(res.hash_result.encode('hex'), '0922d3405faa3d194f82a45830737d5cc6c75d24')

    def test_hmac_interrupted(self):
        """ Test interrupted HMAC. """
        data = 'Sample #2'

        this = self.hsm.hmac_sha1(self.kh, data[:3], final = False)
        res = this.execute()
        self.assertEquals(res.hash_result.encode('hex'), '00' * 20)
        self.assertTrue(self.hsm.echo('hmac unit test'))
        res = this.next(data[3:], final = True).execute()
        self.assertEquals(res.hash_result.encode('hex'), '0922d3405faa3d194f82a45830737d5cc6c75d24')

    def test_hmac_interrupted2(self):
        """ Test AES-interrupted HMAC. """
        data = 'Sample #2'
        plaintext = 'Maverick'.ljust(pyhsm.defines.YHSM_BLOCK_SIZE)
        kh_encrypt = 0x1001
        kh_decrypt = 0x1001

        this = self.hsm.hmac_sha1(self.kh, data[:3], final = False)
        res = this.execute()
        self.assertEquals(res.hash_result.encode('hex'), '00' * 20)
        # AES encrypt-decrypt in the middle of HMAC calculation
        ciphertext = self.hsm.aes_ecb_encrypt(kh_encrypt, plaintext)
        self.assertNotEqual(plaintext, ciphertext)
        decrypted = self.hsm.aes_ecb_decrypt(kh_decrypt, ciphertext)
        self.assertEqual(plaintext, decrypted)
        # continue HMAC
        res = this.next(data[3:], final = True).execute()
        self.assertEquals(res.hash_result.encode('hex'), '0922d3405faa3d194f82a45830737d5cc6c75d24')

    def test_hmac_wrong_key_handle(self):
        """ Test HMAC SHA1 operation with wrong key handle. """
        try:
            res = self.hsm.hmac_sha1(0x01, 'foo').execute()
            self.fail("Expected YHSM_FUNCTION_DISABLED, got %s" % (res))
        except pyhsm.exception.YHSM_CommandFailed, e:
            self.assertEquals(e.status_str, 'YHSM_FUNCTION_DISABLED')
