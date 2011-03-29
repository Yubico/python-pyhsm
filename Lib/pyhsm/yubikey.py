"""
helper functions to work with Yubikeys and YubiHSM
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import string
import exception

__all__ = [
    # constants
    # functions
    # classes
    'YHSM'
]

def validate_yubikey_with_aead(YHSM, from_key, aead, key_handle):
    """
    Try to validate an OTP from a YubiKey using the aead that can decrypt this YubiKey's
    internal secret, using the key_handle for the aead.

    The parameter aead is either a string, or an instance of YHSM_GeneratedAEAD.
    """

    if isinstance(aead, pyhsm.secrets_cmd.YHSM_GeneratedAEAD):
        aead = aead.data

    if type(from_key) is not str:
        raise exception.YHSM_WrongInputType(
            'from_key', type(''), type(from_key))
    if type(aead) is not str:
        raise exception.YHSM_WrongInputType(
            'aead', type(''), type(aead))
    if type(key_handle) is not int:
        raise exception.YHSM_WrongInputType(
            'key_handle', type(1), type(key_handle))

    if len(aead) == 30 * 2:
        aead = aead.decode('hex')

    public_id, otp = split_id_otp(from_key)

    public_id = modhex_decode(public_id)
    otp = modhex_decode(otp)

    return YHSM.validate_aead_otp(public_id.decode('hex'), otp.decode('hex'), key_handle, aead)

def modhex_decode(data):
    """ Convert a modhex string to ordinary hex. """
    t_map = string.maketrans("cbdefghijklnrtuv", "0123456789abcdef")
    return data.translate(t_map)

def modhex_encode(data):
    """ Convert an ordinary hex string to modhex. """
    t_map = string.maketrans("0123456789abcdef", "cbdefghijklnrtuv")
    return data.translate(t_map)

def split_id_otp(from_key):
    """ Separate public id from OTP given a YubiKey OTP as input. """
    if len(from_key) > 32:
        public_id, otp = from_key[:-32], from_key[-32:]
    elif len(from_key) == 32:
        public_id = ''
        otp = from_key
    else:
        assert()
    return public_id, otp
