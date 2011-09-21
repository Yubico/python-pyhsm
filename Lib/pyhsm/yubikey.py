"""
helper functions to work with Yubikeys and YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import string

__all__ = [
    # constants
    # functions
    'validate_otp',
    'validate_yubikey_with_aead',
    'modhex_encode',
    'modhex_decode',
    # classes
 ]

import pyhsm.exception
import pyhsm.aead_cmd

def validate_otp(hsm, from_key):
    """
    Try to validate an OTP from a YubiKey using the internal database
    on the YubiHSM.

    `from_key' is the modhex encoded string emitted when you press the
    button on your YubiKey.
    """
    public_id, otp = split_id_otp(from_key)
    return hsm.db_validate_yubikey_otp(modhex_decode(public_id).decode('hex'),
                                       modhex_decode(otp).decode('hex')
                                       )

def validate_yubikey_with_aead(hsm, from_key, aead, key_handle):
    """
    Try to validate an OTP from a YubiKey using the AEAD that can decrypt this YubiKey's
    internal secret, using the key_handle for the AEAD.

    The parameter `aead' is either a string, or an instance of YHSM_GeneratedAEAD.
    """

    from_key = pyhsm.util.input_validate_str(from_key, 'from_key', max_len = 48)
    aead = pyhsm.util.input_validate_aead(aead)
    key_handle = pyhsm.util.input_validate_key_handle(key_handle)

    public_id, otp = split_id_otp(from_key)

    public_id = modhex_decode(public_id)
    otp = modhex_decode(otp)

    return hsm.validate_aead_otp(public_id.decode('hex'), otp.decode('hex'), key_handle, aead)

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
        raise pyhsm.exception.YHSM_Error("Bad from_key length %i < 32 : %s" \
                                       % (len(from_key), from_key))
    return public_id, otp
