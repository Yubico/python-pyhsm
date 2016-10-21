# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import os
import sys
import unittest
import pyhsm

import test_aead
import test_aes_ecb
import test_basics
import test_buffer
import test_db
import test_hmac
import test_oath
import test_otp_validate
import test_stick
import test_util
import test_yubikey_validate
import test_misc
import test_soft_hsm

test_modules = [test_aead,
                test_aes_ecb,
                test_basics,
                test_buffer,
                test_db,
                test_hmac,
                test_oath,
                test_otp_validate,
                test_stick,
                test_util,
                test_yubikey_validate,
                test_misc,
                test_soft_hsm,
                ]

# special, should not be addded to test_modules
import configure_hsm


def suite():
    """
    Create a test suite with all our tests.

    If the OS environment variable 'YHSM_ZAP' is set and evaluates to true,
    we will include the special test case class that erases the current
    YubiHSM config and creates a new one with known keys to be used by the
    other tests. NOTE that this is ONLY POSSIBLE if the YubiHSM is already
    in DEBUG mode.
    """

    # Check if we have a YubiHSM present, and start with locking it's keystore
    # XXX produce a better error message than 'error: None' when initializing fails
    hsm = pyhsm.YHSM(device = os.getenv('YHSM_DEVICE', '/dev/ttyACM0'))
    try:
        hsm.unlock("BADPASSPHRASE99")
    except pyhsm.exception.YHSM_CommandFailed as e:
        if hsm.version.have_key_store_decrypt():
            if e.status != pyhsm.defines.YSM_MISMATCH:
                raise
        else:
            if e.status != pyhsm.defines.YSM_KEY_STORAGE_LOCKED and \
                    e.status != pyhsm.defines.YSM_FUNCTION_DISABLED:
                raise

    tests = []
    if os.environ.get('YHSM_ZAP'):
        tests.append(unittest.TestLoader().loadTestsFromModule(configure_hsm))
    tests += [unittest.TestLoader().loadTestsFromModule(this) for this in test_modules]

    return unittest.TestSuite(tests)


def load_tests(loader, rests, pattern):
    return suite()


if __name__ == '__main__':
    unittest.main()
