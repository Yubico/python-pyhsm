# Copyright (c) 2011, Yubico AB
# All rights reserved.

import sys
import unittest
import pyhsm

import test_common

class TestBasics(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self, debug=True)

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
        self.assertEqual(n1.nonce + 1, n2.nonce)
        n3 = self.hsm.get_nonce(9)
        # YubiHSM returns nonce _before_ adding increment, so the increment
        # is still only 1 between n2 and n3
        self.assertEqual(n2.nonce + 1, n3.nonce)
        n4 = self.hsm.get_nonce(1)
        # and now we see the 9 increment
        self.assertEqual(n3.nonce + 9, n4.nonce)

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
