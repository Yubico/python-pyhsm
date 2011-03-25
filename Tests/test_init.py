import os
import sys
import unittest
import pyhsm

import test_basics
import test_otp_validate
import test_yubikey_validate

test_modules = [test_basics,
                test_otp_validate,
                test_yubikey_validate,
                ]

# special, should not be addded to test_modules
import test_configure

def suite():
    """
    Create a test suite with all our tests.

    If the OS environment variable 'YHSM_ZAP' is set and evaluates to true,
    we will include the special test case class that erases the current
    YubiHSM config and creates a new one with known keys to be used by the
    other tests. NOTE that this is ONLY POSSIBLE if the YubiHSM is already
    in DEBUG mode.
    """

    global test_modules

    zap = []
    if 'YHSM_ZAP' in os.environ:
        if os.environ['YHSM_ZAP']:
            zap = [unittest.TestLoader().loadTestsFromModule(test_configure)]

    l = zap + [unittest.TestLoader().loadTestsFromModule(this) for this in test_modules]

    return unittest.TestSuite(l)

if __name__ == '__main__':
    unittest.main()
