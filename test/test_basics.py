# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import sys
import unittest
import pyhsm
import serial
import struct

import test_common

class TestBasics(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)

    def test_echo(self):
        """ Test echo command. """
        self.assertTrue(self.hsm.echo('test'))

    def test_random(self):
        """ Test random number generator . """
        r1 = self.hsm.random(10)
        r2 = self.hsm.random(10)
        self.assertNotEqual(r1, r2)
        self.assertEqual(len(r1), 10)

    def test_util_key_handle_to_int(self):
        """ Test util.key_handle_to_int. """
        self.assertEqual(1, pyhsm.util.key_handle_to_int("1"))
        self.assertEqual(1, pyhsm.util.key_handle_to_int("0x1"))
        self.assertEqual(0xffffffee, pyhsm.util.key_handle_to_int("0xffffffee"))
        self.assertEqual(1413895238, pyhsm.util.key_handle_to_int("FTFT"))

    def test_nonce(self):
        """ Test nonce retreival. """
        n1 = self.hsm.get_nonce()
        n2 = self.hsm.get_nonce()
        self.assertEqual(n1.nonce_int + 1, n2.nonce_int)
        n3 = self.hsm.get_nonce(9)
        # YubiHSM returns nonce _before_ adding increment, so the increment
        # is still only 1 between n2 and n3
        self.assertEqual(n2.nonce_int + 1, n3.nonce_int)
        n4 = self.hsm.get_nonce(1)
        # and now we see the 9 increment
        self.assertEqual(n3.nonce_int + 9, n4.nonce_int)

    def test_nonce_class(self):
        """ Test nonce class. """
        # test repr method
        self.assertEquals(str, type(str(self.hsm.get_nonce(0))))

    def test_random_reseed(self):
        """
        Tets random reseed.
        """
        # Unsure if we can test anything except the status returned is OK
        self.assertTrue(self.hsm.random_reseed('A' * 32))
        # at least test we didn't disable the RNG
        r1 = self.hsm.random(10)
        r2 = self.hsm.random(10)
        self.assertNotEqual(r1, r2)

    def test_load_temp_key(self):
        """ Test load_temp_key. """
        key = "A" * 16
        uid = '\x4d\x01\x4d\x02'
        nonce = 'f1f2f3f4f5f6'.decode('hex')
        # key 0x2000 has all flags set
        key_handle = 0x2000

        my_flags = struct.pack("< I", 0xffffffff) # full permissions when loaded into phantom key handle
        my_key = 'C' * pyhsm.defines.YSM_MAX_KEY_SIZE
        self.hsm.load_secret(my_key + my_flags)

        aead = self.hsm.generate_aead(nonce, key_handle)

        self.assertTrue(isinstance(aead, pyhsm.aead_cmd.YHSM_GeneratedAEAD))

        # Load the AEAD into the phantom key handle 0xffffffff.
        self.assertTrue(self.hsm.load_temp_key(nonce, key_handle, aead))

        # Encrypt something with the phantom key
        plaintext = 'Testing'.ljust(pyhsm.defines.YSM_BLOCK_SIZE)	# pad for compare after decrypt
        ciphertext = self.hsm.aes_ecb_encrypt(pyhsm.defines.YSM_TEMP_KEY_HANDLE, plaintext)
        self.assertNotEqual(plaintext, ciphertext)

        # Now decrypt it again and verify result
        decrypted = self.hsm.aes_ecb_decrypt(pyhsm.defines.YSM_TEMP_KEY_HANDLE, ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_yhsm_class(self):
        """ Test YHSM class. """
        # test repr method
        self.assertEquals(str, type(str(self.hsm)))

    def test_yhsm_stick_class(self):
        """ Test YHSM_Stick class. """
        # test repr method
        self.assertEquals(str, type(str(self.hsm.stick)))

    def test_set_debug(self):
        """ Test set_debug on YHSM. """
        old = self.hsm.set_debug(True)
        if old:
            self.hsm.set_debug(False)
        self.hsm.set_debug(old)
        try:
            self.hsm.set_debug('Test')
            self.fail("Expected non-bool exception.")
        except pyhsm.exception.YHSM_WrongInputType:
            pass

    def test_sysinfo_cmd_class(self):
        """ Test YHSM_Cmd_System_Info class. """
        this = pyhsm.basic_cmd.YHSM_Cmd_System_Info(None)
        # test repr method
        self.assertEquals(str, type(str(this)))

    def test_sysinfo(self):
        """ Test sysinfo. """
        info = self.hsm.info()
        self.assertTrue(info.version_major > 0 or info.version_minor > 0)
        self.assertEqual(12, len(info.system_uid))
        self.assertEquals(str, type(str(info)))

    def test_drain(self):
        """ Test YubiHSM drain. """
        self.hsm.drain()

    def test_raw_device(self):
        """ Test YubiHSM raw device fetch. """
        self.assertNotEqual(False, self.hsm.get_raw_device())

    def test_unknown_defines(self):
        """ Test command/response to string. """
        self.assertEqual("YSM_NULL", pyhsm.defines.cmd2str(0))
        self.assertEqual("0xff", pyhsm.defines.cmd2str(0xff))
        self.assertEqual("YSM_STATUS_OK", pyhsm.defines.status2str(0x80))
        self.assertEqual("0x00", pyhsm.defines.status2str(0))
