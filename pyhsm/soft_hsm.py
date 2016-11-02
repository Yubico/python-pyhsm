"""
functions for implementing parts of the HSMs machinery in software
"""

# Copyright (c) 2012 Yubico AB
# See the file COPYING for licence statement.

import struct
import json
import os

__all__ = [
    # constants
    # functions
    'aesCCM',
    'crc16',
    # classes
    'SoftYHSM'
]

import pyhsm
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


def crc16(data):
    """
    Calculate an ISO13239 CRC checksum of the input buffer.
    """
    m_crc = 0xffff
    for this in data:
        m_crc ^= ord(this)
        for _ in range(8):
            j = m_crc & 1
            m_crc >>= 1
            if j:
                m_crc ^= 0x8408
    return m_crc


class SoftYHSM(object):
    def __init__(self, keys, debug=False):
        self._buffer = ''
        self.debug = debug
        if not keys:
            raise ValueError('Data contains no key handles!')
        for k, v in keys.items():
            if len(v) not in AES.key_size:
                raise ValueError('Keyhandle of unsupported length: %d (was %d bytes)' % (k, len(v)))
        self.keys = keys

    @classmethod
    def from_file(cls, filename, debug=False):
        with open(filename, 'r') as f:
            return cls.from_json(f.read(), debug)

    @classmethod
    def from_json(cls, data, debug=False):
        data = json.loads(data)
        if not isinstance(data, dict):
            raise ValueError('Data does not contain object as root element.')
        keys = {}
        for kh, aes_key_hex in data.items():
            keys[int(kh)] = aes_key_hex.decode('hex')
        return cls(keys, debug)

    def _get_key(self, kh, cmd):
        try:
            return self.keys[kh]
        except KeyError:
            raise pyhsm.exception.YHSM_CommandFailed(
                pyhsm.defines.cmd2str(cmd),
                pyhsm.defines.YSM_KEY_HANDLE_INVALID)

    def validate_aead_otp(self, public_id, otp, key_handle, aead):
        aes_key = self._get_key(key_handle, pyhsm.defines.YSM_AEAD_YUBIKEY_OTP_DECODE)
        cmd = pyhsm.validate_cmd.YHSM_Cmd_AEAD_Validate_OTP(
            None, public_id, otp, key_handle, aead)

        aead_pt = aesCCM(aes_key, cmd.key_handle, cmd.public_id, aead, True)
        yk_key, yk_uid = aead_pt[:16], aead_pt[16:]

        ecb_aes = AES.new(yk_key, AES.MODE_ECB)
        otp_plain = ecb_aes.decrypt(otp)

        uid = otp_plain[:6]
        use_ctr, ts_low, ts_high, session_ctr, rnd, crc = struct.unpack(
            '<HHBBHH', otp_plain[6:])

        if uid == yk_uid and crc16(otp_plain) == 0xf0b8:
            return pyhsm.validate_cmd.YHSM_ValidationResult(
                cmd.public_id, use_ctr, session_ctr, ts_high, ts_low
            )

        raise pyhsm.exception.YHSM_CommandFailed(
            pyhsm.defines.cmd2str(cmd.command), pyhsm.defines.YSM_OTP_INVALID)

    def load_secret(self, secret):
        self._buffer = secret.pack()

    def load_random(self, num_bytes, offset = 0):
        self._buffer = self._buffer[:offset] + os.urandom(num_bytes)

    def generate_aead(self, nonce, key_handle):
        aes_key = self._get_key(key_handle, pyhsm.defines.YSM_BUFFER_AEAD_GENERATE)
        ct = pyhsm.soft_hsm.aesCCM(aes_key, key_handle, nonce, self._buffer,
                                   False)
        return pyhsm.aead_cmd.YHSM_GeneratedAEAD(nonce, key_handle, ct)
