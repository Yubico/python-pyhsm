"""
functions for implementing parts of the HSMs machinery in software
"""

# Copyright (c) 2012 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    'aesCCM',
    # classes
]

import pyhsm.exception
from Crypto.Cipher import AES

def _xor_block(a, b):
    """ XOR two blocks of equal length. """
    return ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])

class _ctr_counter():
    """
    An object implementation of the struct aesCtr.
    """
    def __init__(self, key_handle, nonce, flags = None, value = 0):
        self.flags = pyhsm.defines.YSM_CCM_CTR_SIZE - 1 if flags is None else flags
        self.key_handle = key_handle
        self.nonce = nonce
        self.value = value

    def next(self):
        """
        Return next counter value, encoded into YSM_BLOCK_SIZE.
        """
        self.value += 1
        return self.pack()

    def pack(self):
        fmt = b'< B I %is BBB 2s' % (pyhsm.defines.YSM_AEAD_NONCE_SIZE)
        val = struct.pack('> H', self.value)
        return struct.pack(fmt,
                           self.flags,
                           self.key_handle,
                           self.nonce,
                           0, 0, 0, # rfu
                           val
                           )

class _cbc_mac():
    def __init__(self, key, key_handle, nonce, data_len):
        """
        Initialize CBC-MAC like the YubiHSM does.
        """
        flags = (((pyhsm.defines.YSM_AEAD_MAC_SIZE - 2) / 2) << 3) | (pyhsm.defines.YSM_CCM_CTR_SIZE - 1)
        t = _ctr_counter(key_handle, nonce, flags = flags, value = data_len)
        t_mac = t.pack()
        self.mac_aes = AES.new(key, AES.MODE_ECB)
        self.mac = self.mac_aes.encrypt(t_mac)

    def update(self, block):
        block = block.ljust(pyhsm.defines.YSM_BLOCK_SIZE, chr(0x0))
        t1 = _xor_block(self.mac, block)
        t2 = self.mac_aes.encrypt(t1)
        self.mac = t2

    def finalize(self, block):
        """
        The final step of CBC-MAC encrypts before xor.
        """
        t1 = self.mac_aes.encrypt(block)
        t2 = _xor_block(self.mac, t1)
        self.mac = t2

    def get(self):
        return self.mac[: pyhsm.defines.YSM_AEAD_MAC_SIZE]


def _split_data(data, pos):
    a = data[:pos]
    b = data[pos:]
    return (a, b,)

def aesCCM(key, key_handle, nonce, data, decrypt=False):
    """
    Function implementing YubiHSM AEAD encrypt/decrypt in software.
    """
    if decrypt:
        (data, saved_mac) = _split_data(data, len(data) - pyhsm.defines.YSM_AEAD_MAC_SIZE)

    nonce = pyhsm.util.input_validate_nonce(nonce, pad = True)
    mac = _cbc_mac(key, key_handle, nonce, len(data))

    counter = _ctr_counter(key_handle, nonce, value = 0)
    ctr_aes = AES.new(key, AES.MODE_CTR, counter = counter.next)
    out = []
    while data:
        (thisblock, data) = _split_data(data, pyhsm.defines.YSM_BLOCK_SIZE)

        # encrypt/decrypt and CBC MAC
        if decrypt:
            aes_out = ctr_aes.decrypt(thisblock)
            mac.update(aes_out)
        else:
            mac.update(thisblock)
            aes_out = ctr_aes.encrypt(thisblock)

        out.append(aes_out)

    # Finalize MAC
    counter.value = 0
    mac.finalize(counter.pack())
    if decrypt:
        if mac.get() != saved_mac:
            raise pyhsm.exception.YHSM_Error('AEAD integrity check failed')
    else:
        out.append(mac.get())
    return ''.join(out)
