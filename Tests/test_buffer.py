# Copyright (c) 2011, Yubico AB
# All rights reserved.

import sys
import unittest
import pyhsm

import test_common

class TestBuffer(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)

    def test_load_random(self):
        """ Test load_random. """
        nonce = "abc123"
        # key 0x2000 has all flags set
        key_handle = 0x2000
        self.hsm.load_random(16)
        aead1 = self.hsm.generate_aead(nonce, key_handle)
        # nonce should NEVER be re-used for the same key_handle, but
        # we do it to test that the random-function actually changes
        # the buffer.
        self.hsm.load_random(16)
        aead2 = self.hsm.generate_aead(nonce, key_handle)

        self.assertNotEqual(aead1.data, aead2.data)
