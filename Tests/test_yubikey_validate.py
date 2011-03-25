import os
import sys
import string
import struct
import unittest
import pyhsm
from Crypto.Cipher import AES

import test_common

# Copyright (c) 2011, Yubico AB
# All rights reserved.

def validate_yubikey_with_blob(YHSM, from_key, blob, key_handle):
    """
    Try to validate an OTP from a YubiKey using the blob that can decrypt this YubiKey's
    internal secret, using the key_handle for the blob.

    The parameter blob is either a string, or an instance of YHSM_GeneratedBlob.
    """

    try:
        # check if blob is an instance of something with a 'blob' attribute
        blob = blob.blob
    except AttributeError:
        pass

    if type(from_key) is not str:
        raise exception.YHSM_WrongInputType(
            'from_key', type(''), type(from_key))
    if type(blob) is not str:
        raise exception.YHSM_WrongInputType(
            'blob', type(''), type(blob))
    if type(key_handle) is not int:
        raise exception.YHSM_WrongInputType(
            'key_handle', type(1), type(key_handle))

    if len(blob) == 48 * 2:
        blob = blob.decode('hex')

    public_id, otp = split_id_otp(from_key)

    public_id = modhex_decode(public_id)
    otp = modhex_decode(otp)

    return YHSM.validate_blob_otp(public_id.decode('hex'), otp.decode('hex'), key_handle, blob)


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


class YubiKeyEmu():
    """
    Emulate the internal memory of a YubiKey.
    """

    def __init__(self, user_id, session_counter, timestamp, session_use):
        if len(user_id) != pyhsm.defines.UID_SIZE:
            raise pyhsm.exception.YHSM_WrongInputSize(
                'user_id', pyhsm.defines.UID_SIZE, len(user_id))

        self.user_id = user_id
        self.session_counter = session_counter
        self.timestamp = timestamp
        self.session_use = session_use
        self.rnd = struct.unpack('H', os.urandom(2))[0]

    def pack(self):
        """
        Return contents packed. Only add AES ECB encryption and modhex to
        get your own YubiKey OTP.
        """

        #define UID_SIZE 6
	#typedef struct {
        #  uint8_t userId[UID_SIZE];
        #  uint16_t sessionCtr;
        #  uint24_t timestamp;
        #  uint8_t sessionUse;
        #  uint16_t rnd;
        #  uint16_t crc;
	#} TICKET;

        ts_high = (self.timestamp & 0x00ff0000) >> 16
        ts_low  =  self.timestamp & 0x0000ffff

        res = self.user_id + struct.pack('<HHBBH', \
                                             self.session_counter, \
                                             ts_low, \
                                             ts_high, \
                                             self.session_use, \
                                             self.rnd)
        crc = 0xffff - crc16(res)

        return res + struct.pack('<H', crc)


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
        self.hsm = pyhsm.base.YHSM(device = "/dev/ttyACM0", debug = False)

        # Check that this is a device we know how to talk to
        assert(self.hsm.info().protocolVersion == 1)

        self.yk_key = 'F' * 16	# 128 bit AES key
        self.yk_uid = '\x4d\x01\x4d\x02\x4d\x4d'
        self.yk_rnd = YubiKeyRnd(self.yk_uid)
        self.yk_public_id = '4d4d4d4d4d4d'.decode('hex')

        secret = pyhsm.secrets_cmd.YHSM_Secrets(self.yk_key, self.yk_uid)
        self.hsm.load_secret(self.yk_public_id, secret)

        #self.kh_generate = 0x06		# key handle 0x9 is allowed to generate blobs
        #self.kh_validate = 0x1000	# key handle 0x1000 is allowed to validate blobs and have the same key as 0x9

        # current YubiHSM includes key handle id in AES-CCM of blobs, so we must use same
        # key to generate and validate. Key 0x2000 has all flags.
        self.kh_generate = 0x2000
        self.kh_validate = 0x2000

        self.blob = self.hsm.generate_blob(self.kh_generate)

    def test_validate_yubikey(self):
        """ Test validate YubiKey OTP. """

        # encrypt our fake yubikey
        obj = AES.new(self.yk_key, AES.MODE_ECB)
        ciphertext = obj.encrypt(self.yk_rnd.pack())
        mh_ciphertext = modhex_encode(ciphertext.encode('hex'))
        from_key = modhex_encode(self.yk_public_id.encode('hex')) + mh_ciphertext

        self.assertTrue(validate_yubikey_with_blob(self.hsm, from_key, self.blob, self.kh_validate))

    def test_modhex_encode_decode(self):
        """ Test modhex encoding/decoding. """
        h = '4d014d024d4ddd5382b11195144da07d'
        self.assertEquals(h, modhex_decode( modhex_encode(h) ) )
