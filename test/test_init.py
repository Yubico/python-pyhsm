# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import os
import sys
import unittest
import pyhsm

from . import test_aead
from . import test_aes_ecb
from . import test_basics
from . import test_buffer
from . import test_db
from . import test_hmac
from . import test_oath
from . import test_otp_validate
from . import test_stick
from . import test_util
from . import test_yubikey_validate
from . import test_misc
from . import test_soft_hsm
from . import configure_hsm

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
        hsm.unlock(b"BADPASSPHRASE99")
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
