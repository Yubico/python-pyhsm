#!/usr/bin/env python
#
# Utility to generate an AEAD (encrypted block) from a password,
# that can later on be validated securely.
#
# Copyright (c) 2011, Yubico AB
# All rights reserved.
#
# If you only have a single YubiHSM, you have to have one key handle
# that can both ENCRYPT and COMPARE AES ECB blocks.
#
# If you have two (or more) YubiHSM's, you can have a key handle in
# YubiHSM 1 that can only ENCRYPT, and the same key (!) with the same
# key handle (!) in YubiHSM 2 that can only COMPARE. This might add
# to the overall security in certain applications.
#
#
# Example usage :
#
# First, set password (create AEAD) :
#
#   $ ./examples/yhsm-password-auth.py --key-handle 8192 --nonce abc --verbose --set
#   Enter password to encrypt : <enter password>
#   Success! Remember the nonce and use this AEAD to validate the password later :
#
#   AEAD: edee7db15eb1efb35bdcc7a39d2b3ec0 NONCE: 'abc'
#   $
#
# Then, later on, validate the password using the AEAD and NONCE from above :
#
#   $ ./examples/yhsm-password-auth.py --key-handle 8192 --nonce abc --verbose \
#					--validate edee7db15eb1efb35bdcc7a39d2b3ec0
#   Enter password to validate : <enter same password again>
#   OK! Password validated.
#   $
#

import sys
sys.path.append('Lib');
import pyhsm
import argparse
import getpass

default_device = "/dev/ttyACM0"

def parse_args():
    """
    Parse the command line arguments
    """
    global default_device

    parser = argparse.ArgumentParser(description = "Generate password AEAD using YubiHSM",
                                     add_help=True
                                     )
    parser.add_argument('-D', '--device',
                        dest='device',
                        default=default_device,
                        required=False,
                        help='YubiHSM device (default : "%s").' % default_device
                        )
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true', default=False,
                        help='Enable verbose operation.'
                        )
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=False,
                        help='Enable debug operation.'
                        )
    parser.add_argument('--key-handle',
                        type=int, dest='key_handle',
                        required=True,
                        help='Key handle to use. Must have YHSM_ECB_BLOCK_ENCRYPT and/or YHSM_ECB_BLOCK_DECRYPT_CMP flag set.'
                        )
    parser.add_argument('-N', '--nonce',
                        dest='nonce',
                        required=True,
                        help='Nonce to use. Could be username.'
                        )
    parser.add_argument('--set',
                        dest='set',
                        action='store_true', default=False,
                        help='Set password mode.'
                        )
    parser.add_argument('--validate',
                        dest='validate',
                        help='AEAD to validate.'
                        )

    args = parser.parse_args()

    if args.set and args.validate:
        sys.stderr.write("Arguments --set and --validate are mutually exclusive.\n")
        sys.exit(1)
    if not args.set and not args.validate:
        sys.stderr.write("Either --set or --validate must be specified.\n")
        sys.exit(1)

    return args

def generate_aead(hsm, args, password):
    """
    Generate an AEAD using the YubiHSM.
    """
    plaintext = ":".join([args.nonce, password])
    try:
        ciphertext = hsm.aes_ecb_encrypt(args.key_handle, plaintext)
        return ciphertext
    except pyhsm.exception.YHSM_CommandFailed, e:
        if e.status_str == 'YHSM_FUNCTION_DISABLED':
            print "ERROR: The key handle %s is not permitted to do AES ECB encrypt." % (args.key_handle)
            return None
        else:
            print "ERROR: %s" % (e.reason)

def validate_aead(hsm, args, password):
    """
    Validate a previously generated AEAD using the YubiHSM.
    """
    plaintext = ":".join([args.nonce, password])
    try:
        return hsm.aes_ecb_compare(args.key_handle, args.validate.decode('hex'), plaintext)
    except pyhsm.exception.YHSM_CommandFailed, e:
        if e.status_str == 'YHSM_FUNCTION_DISABLED':
            print "ERROR: The key handle %s is not permitted to do AES ECB compare." % (args.key_handle)
            return None
        else:
            print "ERROR: %s" % (e.reason)

def main():
    args = parse_args()

    what="encrypt"
    if args.validate:
        what="validate"
    user_input = getpass.getpass('Enter password to %s : ' % (what))
    if not user_input:
        print "\nAborted.\n"
        return 0

    try:
        hsm = pyhsm.base.YHSM(device=args.device, debug=args.debug)
    except pyhsm.exception.YHSM_Error, e:
        print "ERROR: %s" % e
        return 1

    if args.set:
        #
        # SET password
        #
        aead = generate_aead(hsm, args, user_input)
        if not aead:
            return 1

        if args.verbose:
            print "Success! Remember the nonce and use this AEAD to validate the password later :\n"
        print "AEAD: %s NONCE: '%s'" % (aead.encode('hex'), args.nonce)
    else:
        #
        # VALIDATE password
        #
        if not validate_aead(hsm, args, user_input):
            if args.verbose:
                print "FAIL! Password does not match the generated AEAD."
            return 1
        if args.verbose:
            print "OK! Password validated."

    return 0

if __name__ == '__main__':
    res = main()
    sys.exit(res)
