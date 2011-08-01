#!/usr/bin/env python
#
# Copyright (c) 2011, Yubico AB
# All rights reserved.
#
"""
Utility to unlock the key store of a YubiHSM, using the 'HSM password'.
"""

import sys
sys.path.append('Lib')
import pyhsm
import argparse
import getpass

default_device = "/dev/ttyACM0"

def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description = "Unlock key store of YubiHSM",
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                                     )
    parser.add_argument('-D', '--device',
                        dest='device',
                        default=default_device,
                        required=False,
                        help='YubiHSM device',
                        )
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true', default=False,
                        help='Enable verbose operation'
                        )
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=False,
                        help='Enable debug operation'
                        )

    args = parser.parse_args()

    return args

def main():
    """
    What will be executed when running as a stand alone program.
    """
    args = parse_args()

    try:
        hsm = pyhsm.base.YHSM(device=args.device, debug=args.debug)

        print "Version : %s\n" % (hsm.info())

        if args.debug:
            password = raw_input('Enter HSM password (will be echoed) : ')
        else:
            password = getpass.getpass('Enter HSM password : ')

        if len(password) == 32:
            password = password.decode('hex')
            if args.verbose or args.debug:
                print "\n"
            hsm.key_storage_unlock(password)
            if args.verbose or args.debug:
                print "OK"
        else:
            sys.stderr.write("Invalid HSM password\n")
            return 1
    except pyhsm.exception.YHSM_Error, e:
        sys.stderr.write("ERROR: %s\n" % (e))
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
