# Copyright (c) 2011, Yubico AB
# All rights reserved.

import sys
import unittest
import pyhsm

class YHSM_TestCase(unittest.TestCase):

    hsm = None

    def setUp(self, device = "/dev/ttyACM0", debug = False):
        """
        Common initialization class for our tests. Initializes a
        YubiHSM in self.hsm.
        """
        self.hsm = pyhsm.base.YHSM(device = device, debug = debug)

        # Check that this is a device we know how to talk to
        assert(self.hsm.info().protocol_ver == 1)

    def tearDown(self):
        # get destructor called properly
        self.hsm = None

    def who_can(self, what, expected = []):
        """
        Try the lambda what() with all key handles between 1 and 32, except the expected one.
        Fail on anything but YSM_FUNCTION_DISABLED.
        """
        for kh in xrange(1, 32):
            if kh in expected:
                continue
            res = None
            try:
                res = what(kh)
                self.fail("Expected YSM_FUNCTION_DISABLED for key handle 0x%0x, got '%s'" % (kh, res))
            except pyhsm.exception.YHSM_CommandFailed, e:
                if e.status != pyhsm.defines.YSM_FUNCTION_DISABLED:
                    self.fail("Expected YSM_FUNCTION_DISABLED for key handle 0x%0x, got %s" \
                                  % (kh, e.status_str))
