"""
implementation of YUBIKEY_SECRETS
"""

# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_YubiKeySecret',
]

from cmd import YHSM_Cmd
import exception

class YHSM_YubiKeySecret():
    """ Small class to represent a YUBIKEY_SECRETS struct. """
    def __init__(self, key, uid):
        if len(key) != defines.KEY_SIZE:
            raise exception.YHSM_WrongInputSize(
                'key', defines.KEY_SIZE, len(key))

        if type(uid) is not str:
            raise exception.YHSM_WrongInputType(
                'uid', type(''), type(uid))

        self.key = key
        self.uid = uid

    def pack(self):
        """ Return key and uid packed for sending in a command to the YubiHSM. """
        # # 22-bytes Yubikey secrets block
        # typedef struct {
        #   uint8_t key[KEY_SIZE];              // AES key
        #   uint8_t uid[UID_SIZE];              // Unique (secret) ID
        # } YUBIKEY_SECRETS;
        return self.key + self.uid.ljust(defines.UID_SIZE, chr(0))
