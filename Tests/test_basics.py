# Copyright (c) 2011, Yubico AB
# All rights reserved.

import sys
import unittest
import pyhsm

import test_common

class TestBasics(test_common.YHSM_TestCase):

    def test_echo(self):
        """ Test echo command. """
        self.assertTrue(self.hsm.echo('test'))

    def test_random(self):
        """ Test random number generator . """
        r1 = self.hsm.random(10)
        r2 = self.hsm.random(10)
        self.assertNotEqual(r1, r2)

    def test_util_key_handle_to_int(self):
        """ Test util.key_handle_to_int. """
        self.assertEqual(1, pyhsm.util.key_handle_to_int("1"))
        self.assertEqual(1, pyhsm.util.key_handle_to_int("0x1"))
        self.assertEqual(0xffffffee, pyhsm.util.key_handle_to_int("0xffffffee"))
        self.assertEqual(1413895238, pyhsm.util.key_handle_to_int("FTFT"))
