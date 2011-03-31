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
