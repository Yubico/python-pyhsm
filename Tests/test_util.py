# Copyright (c) 2011, Yubico AB
# All rights reserved.

import sys
import unittest
import pyhsm

import test_common

class TestUtil(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)

    def test_hexdump(self):
        """ Test hexdump function. """
        data1 = ''.join([chr(x) for x in xrange(8)])
        self.assertEquals('0000   00 01 02 03 04 05 06 07\n', pyhsm.util.hexdump(data1))
        data2 = ''.join([chr(x) for x in xrange(64)])
        self.assertEquals(248, len(pyhsm.util.hexdump(data2)))
        self.assertEquals('', pyhsm.util.hexdump(''))

    def test_response_validation(self):
        """ Test response validation functions. """
        self.assertRaises(pyhsm.exception.YHSM_Error, pyhsm.util.validate_cmd_response_str, \
                              'test', 'abc', 'def', hex_encode=True)

        self.assertRaises(pyhsm.exception.YHSM_Error, pyhsm.util.validate_cmd_response_str, \
                              'test', 'abc', 'def', hex_encode=False)
