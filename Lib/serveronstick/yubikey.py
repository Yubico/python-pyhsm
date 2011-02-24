"""
helper functions to work with Yubikeys and Server on a Stick
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import string
import exception

__all__ = [
    # constants
    # functions
    # classes
    'SoS'
]

def validate_yubikey_with_blob(SoS, from_key, blob, key_handle):
    """
    Try to validate an OTP from a YubiKey using the blob that can decrypt this YubiKey's
    internal secret, using the key_handle for the blob.

    The parameter blob is either a string, or an instance of SoS_GeneratedBlob.
    """

    try:
        # check if blob is an instance of something with a 'blob' attribute
        blob = blob.blob
    except AttributeError:
        pass

    if type(from_key) is not str:
        raise exception.SoS_WrongInputType(
            'from_key', type(''), type(from_key))
    if type(blob) is not str:
        raise exception.SoS_WrongInputType(
            'blob', type(''), type(blob))
    if type(key_handle) is not int:
        raise exception.SoS_WrongInputType(
            'key_handle', type(1), type(key_handle))

    if len(blob) == 48 * 2:
        blob = blob.decode('hex')

    if len(from_key) > 32:
        public_id, otp = from_key[:-32], from_key[-32:]
    elif len(from_key) == 32:
        public_id = ''
        otp = from_key
    else:
        assert()

    public_id = modhex_decode(public_id)
    otp = modhex_decode(otp)

    return SoS.validate_blob_otp(public_id.decode('hex'), otp.decode('hex'), key_handle, blob)

def modhex_decode(data):
    """ Convert a modhex string to ordinary hex. """
    t_map = string.maketrans("cbdefghijklnrtuv", "0123456789abcdef")
    return data.translate(t_map)
