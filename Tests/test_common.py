import sys
import unittest
import serveronstick

class YHSM_TestCase(unittest.TestCase):

    hsm = None

    def setUp(self):
        self.hsm = serveronstick.base.SoS(device = "/dev/ttyACM0")

        # Check that this is a device we know how to talk to
        assert(self.hsm.info().protocolVersion == 1)

    def tearDown(self):
        # get destructor called properly
        self.hsm = None
