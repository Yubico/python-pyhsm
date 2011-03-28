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
