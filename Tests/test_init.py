import sys
import unittest
import serveronstick

import test_basics

class TestInit(unittest.TestCase):

    hsm = None

    def setUp(self):
        self.hsm = serveronstick.base.SoS("/dev/ttyACM0")

        # Check that this is a device we know how to talk to
        assert(self.hsm.info().protocolVersion == 1)

def suite():
    global test_modules

    l = [
        unittest.TestLoader().loadTestsFromModule(test_basics)
        ]

    suite = unittest.TestSuite(l)

    return suite

if __name__ == '__main__':
    unittest.main()
