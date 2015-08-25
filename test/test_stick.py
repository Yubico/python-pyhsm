# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import sys
import unittest
import pyhsm

import test_common

class TestUtil(test_common.YHSM_TestCase):

    def setUp(self):
        self.saved_stderr = sys.stderr
        # Discard everything written to stderr from these tests (i.e. debug output
        # from YubiHSM communication routines with debugging enabled).
        sys.stderr = DiscardOutput()
        DontChange = True # we test debug output from YubiHSM communication here
        test_common.YHSM_TestCase.setUp(self, debug = DontChange)

    def test_debug_output(self):
        """ Test debug output of YubiHSM communication. """
        self.assertTrue(self.hsm.echo('testing'))
        self.assertTrue(self.hsm.drain())

    def tearDown(self):
        # Close YubiHSM interface before restoring stderr, to avoid output
        # when it is closed.
        self.hsm = None
        sys.stderr = self.saved_stderr

class DiscardOutput(object):
    def write(self, text):
        pass
