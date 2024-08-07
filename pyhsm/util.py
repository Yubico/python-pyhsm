"""
collection of utility functions
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    'hexdump',
    'group',
    'key_handle_to_int',
    # classes
]

import pyhsm.exception

def hexdump(src, length=8):
    """ Produce a string hexdump of src, for debug output."""
    if not src:
        return str(src)
    src = input_validate_str(src, 'src')
    offset = 0
    result = ''
    for this in group(src, length):
        hex_s = ' '.join(["%02x" % x for x in this])
        result += "%04X   %s\n" % (offset, hex_s)
        offset += length
    return result

def group(data, num):
    """ Split data into chunks of num chars each """
    return [data[i:i+num] for i in range(0, len(data), num)]

def key_handle_to_int(this):
    """
    Turn "123" into 123 and "KSM1" into 827151179
    (0x314d534b, 'K' = 0x4b, S = '0x53', M = 0x4d).

    YHSM is little endian, so this makes the bytes KSM1 appear
    in the most human readable form in packet traces.
    """
    try:
        num = int(this)
        return num
    except ValueError:
        if this[:2] == "0x":
            return int(this, 16)
        if (len(this) == 4):
            num = struct.unpack('<I', this.encode())[0]
            return num
    raise pyhsm.exception.YHSM_Error("Could not parse key_handle '%s'" % (this))

def input_validate_str(string, name, max_len=None, exact_len=None):
    """ Input validation for strings. NOW CHANGED TO BYTES""" 
    if type(string) is not bytes:
        raise pyhsm.exception.YHSM_WrongInputType(name, bytes, type(string))
    if max_len != None and len(string) > max_len:
        raise pyhsm.exception.YHSM_InputTooLong(name, max_len, len(string))
    if exact_len != None and len(string) != exact_len:
        raise pyhsm.exception.YHSM_WrongInputSize(name, exact_len, len(string))
    return string

def input_validate_int(value, name, max_value=None):
    """ Input validation for integers. """
    if type(value) is not int:
        raise pyhsm.exception.YHSM_WrongInputType(name, int, type(value))
    if max_value != None and value > max_value:
        raise pyhsm.exception.YHSM_WrongInputSize(name, max_value, value)
    return value

def input_validate_nonce(nonce, name='nonce', pad = False):
    """ Input validation for nonces. NOW CHANGED TO BYTES"""
    if type(nonce) is not bytes:
        raise pyhsm.exception.YHSM_WrongInputType( \
            name, bytes, type(nonce))
    if len(nonce) > pyhsm.defines.YSM_AEAD_NONCE_SIZE:
        raise pyhsm.exception.YHSM_InputTooLong(
            name, pyhsm.defines.YSM_AEAD_NONCE_SIZE, len(nonce))
    if pad:
        return nonce.ljust(pyhsm.defines.YSM_AEAD_NONCE_SIZE, b'\x00')
    else:
        return nonce

def input_validate_key_handle(key_handle, name='key_handle'):
    """ Input validation for key_handles. NOW CHANGED TO BYTES"""
    if type(key_handle) is not bytes:
        try:
            return key_handle_to_int(key_handle)
        except pyhsm.exception.YHSM_Error:
            raise pyhsm.exception.YHSM_WrongInputType(name, bytes, type(key_handle))
    return key_handle

def input_validate_yubikey_secret(data, name='data'):
    """ Input validation for YHSM_YubiKeySecret or string. """
    if isinstance(data, pyhsm.aead_cmd.YHSM_YubiKeySecret):
        data = data.pack()
    return input_validate_str(data, name)

def input_validate_aead(aead, name='aead', expected_len=None, max_aead_len = pyhsm.defines.YSM_AEAD_MAX_SIZE):
    """ Input validation for YHSM_GeneratedAEAD or string. """
    if isinstance(aead, pyhsm.aead_cmd.YHSM_GeneratedAEAD):
        aead = aead.data
    if expected_len != None:
        return input_validate_str(aead, name, exact_len = expected_len)
    else:
        return input_validate_str(aead, name, max_len=max_aead_len)



def validate_cmd_response_int(name, got, expected):
    """
    Check that some value returned in the response to a command matches what
    we put in the request (the command).
    """
    if got != expected:
        raise(pyhsm.exception.YHSM_Error("Bad %s in response (got %i, expected %i)" \
                                             % (name, got, expected)))
    return got


def validate_cmd_response_hex(name, got, expected):
    """
    Check that some value returned in the response to a command matches what
    we put in the request (the command).
    """
    if got != expected:
        raise(pyhsm.exception.YHSM_Error("Bad %s in response (got 0x%x, expected 0x%x)" \
                                             % (name, got, expected)))
    return got


def validate_cmd_response_str(name, got, expected, hex_encode=True):
    """
    Check that some value returned in the response to a command matches what
    we put in the request (the command).
    """
    if got != expected:
        if hex_encode:
            got_s = got
            exp_s = expected
        else:
            got_s = got
            exp_s = expected
        raise(pyhsm.exception.YHSM_Error("Bad %s in response (got %s, expected %s)" \
                                             % (name, got_s, exp_s)))
    return got

def validate_cmd_response_nonce(got, used):
    """
    Check that the returned nonce matches nonce used in request.

    A request nonce of 000000000000 means the HSM should generate a nonce internally though,
    so if 'used' is all zeros we actually check that 'got' does NOT match 'used'.
    """
    if used == bytes.fromhex('000000000000'):
        if got == used:
            raise(pyhsm.exception.YHSM_Error("Bad nonce in response (got %s, expected HSM generated nonce)" \
                                                 % (bytes.fromhex(got))))
        return got
    return validate_cmd_response_str('nonce', got, used)
