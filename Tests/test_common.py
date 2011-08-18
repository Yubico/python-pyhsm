# Copyright (c) 2011, Yubico AB
# All rights reserved.

import sys
import unittest
import pyhsm

# configuration parameters
CfgPassphrase = ""
HsmPassphrase = "bada" * 2
AdminYubiKeys = ""

class YHSM_TestCase(unittest.TestCase):

    hsm = None

    def setUp(self, device = "/dev/ttyACM0", debug = False):
        """
        Common initialization class for our tests. Initializes a
        YubiHSM in self.hsm.
        """
        self.hsm = pyhsm.base.YHSM(device = device, debug = debug)
        # unlock keystore if our test configuration contains a passphrase
        if HsmPassphrase is not None and HsmPassphrase != "":
            try:
                self.hsm.key_storage_unlock(HsmPassphrase.decode("hex"))
            except pyhsm.exception.YHSM_CommandFailed, e:
                # ignore errors from this one, in case our test configuration
                # hasn't been loaded into the YubiHSM yet
                pass

    def tearDown(self):
        # get destructor called properly
        self.hsm = None

    def who_can(self, what, expected = [], extra_khs = []):
        """
        Try the lambda what() with all key handles between 1 and 32, except the expected one.
        Fail on anything but YSM_FUNCTION_DISABLED.
        """
        for kh in list(xrange(1, 32)) + extra_khs:
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
