# Copyright (c) 2011, Yubico AB
# All rights reserved.

import os
import sys
import string
import struct
import unittest
import pyhsm
from Crypto.Cipher import AES
from pyhsm.yubikey import modhex_encode, modhex_decode

import test_common

class YubiKeyEmu():
    """
    Emulate the internal memory of a YubiKey.
    """

    def __init__(self, user_id, use_ctr, timestamp, session_ctr):
        if len(user_id) != pyhsm.defines.UID_SIZE:
            raise pyhsm.exception.YHSM_WrongInputSize(
                'user_id', pyhsm.defines.UID_SIZE, len(user_id))

        self.user_id = user_id
        self.use_ctr = use_ctr
        self.timestamp = timestamp
        self.session_ctr = session_ctr
        self.rnd = struct.unpack('H', os.urandom(2))[0]

    def pack(self):
        """
        Return contents packed. Only add AES ECB encryption and modhex to
        get your own YubiKey OTP.
        """

        #define UID_SIZE 6
	#typedef struct {
        #  uint8_t userId[UID_SIZE];
        #  uint16_t sessionCtr;		# NOTE: this is use_ctr
        #  uint24_t timestamp;
        #  uint8_t sessionUse;		# NOTE: this is session_ctr
        #  uint16_t rnd;
        #  uint16_t crc;
	#} TICKET;
        fmt = "< %is H HB B H" % (pyhsm.defines.UID_SIZE)

        ts_high = (self.timestamp & 0x00ff0000) >> 16
        ts_low  =  self.timestamp & 0x0000ffff

        res = struct.pack(fmt, self.user_id, \
                              self.use_ctr, \
                              ts_low, ts_high, \
                              self.session_ctr, \
                              self.rnd)
        crc = 0xffff - crc16(res)

        return res + struct.pack('<H', crc)

    def get_otp(self, key):
        """
        Return an modhex encoded OTP given our current state.
        """
        packed = self.pack()
        obj = AES.new(key, AES.MODE_ECB)
        ciphertext = obj.encrypt(packed)
        return ciphertext

    def from_key(self, public_id, key):
        """
        Return what the YubiKey would have returned when the button was pressed.
        """
        otp = self.get_otp(key)
        from_key = modhex_encode(public_id.encode('hex')) + modhex_encode(otp.encode('hex'))
        return from_key

class YubiKeyRnd(YubiKeyEmu):
    """ YubiKeyEmu with everything but user_id randomized. """

    def __init__(self, user_id):
        timestamp, session_counter, session_use = struct.unpack('IHB', os.urandom(7))
        YubiKeyEmu.__init__(self, user_id, session_counter, timestamp, session_use)


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

class TestYubikeyValidate(test_common.YHSM_TestCase):

    def setUp(self):
        test_common.YHSM_TestCase.setUp(self)

        self.yk_key = 'F' * 16	# 128 bit AES key
        self.yk_uid = '\x4d\x01\x4d\x02\x4d\x4d'
        self.yk_rnd = YubiKeyRnd(self.yk_uid)
        self.yk_public_id = '4d4d4d4d4d4d'.decode('hex')

        secret = pyhsm.aead_cmd.YHSM_YubiKeySecret(self.yk_key, self.yk_uid)
        self.hsm.load_secret(secret)

        #self.kh_generate = 0x06		# key handle 0x9 is allowed to generate aeads
        #self.kh_validate = 0x1000	# key handle 0x1000 is allowed to validate aeads and have the same key as 0x9

        # YubiHSM includes key handle id in AES-CCM of aeads, so we must use same
        # key to generate and validate. Key 0x2000 has all flags.
        self.kh_generate = 0x2000
        self.kh_validate = 0x2000

        self.aead = self.hsm.generate_aead(self.yk_public_id, self.kh_generate)

    def test_validate_aead_cmp(self):
        """ Test that the AEAD generated contains our secrets. """
        secret = pyhsm.aead_cmd.YHSM_YubiKeySecret(self.yk_key, self.yk_uid)
        cleartext = secret.pack()
        self.assertTrue(self.hsm.validate_aead(self.yk_public_id, self.kh_validate, self.aead, cleartext))
        wrong_cleartext = 'X' + cleartext[1:]
        self.assertFalse(self.hsm.validate_aead(self.yk_public_id, self.kh_validate, self.aead, wrong_cleartext))

    def test_validate_yubikey(self):
        """ Test validate YubiKey OTP. """
        from_key = self.yk_rnd.from_key(self.yk_public_id, self.yk_key)
        self.assertTrue(pyhsm.yubikey.validate_yubikey_with_aead( \
                self.hsm, from_key, self.aead.data, self.kh_validate))

    def test_modhex_encode_decode(self):
        """ Test modhex encoding/decoding. """
        h = '4d014d024d4ddd5382b11195144da07d'
        self.assertEquals(h, modhex_decode( modhex_encode(h) ) )

    def test_split_id_otp(self):
        """ Test public_id + OTP split function. """
        public_id, otp, = pyhsm.yubikey.split_id_otp("ft" * 16)
        self.assertEqual(public_id, '')
        self.assertEqual(otp, "ft" * 16)

        public_id, otp, = pyhsm.yubikey.split_id_otp("cc" + "ft" * 16)
        self.assertEqual(public_id, 'cc')
        self.assertEqual(otp, "ft" * 16)
