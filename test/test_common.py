# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import os
import sys
import unittest
import pyhsm
import struct

# configuration parameters
CfgPassphrase = ""
HsmPassphrase = "bada" * 2
PrimaryAdminYubiKey = ('ftftftfteeee', 'f0f1f2f3f4f5', '4d' * 16,)
AdminYubiKeys = [PrimaryAdminYubiKey[0]]

class YHSM_TestCase(unittest.TestCase):

    hsm = None

    def setUp(self, device = os.getenv('YHSM_DEVICE', '/dev/ttyACM0'), debug = False):
        """
        Common initialization class for our tests. Initializes a
        YubiHSM in self.hsm.
        """
        self.hsm = pyhsm.base.YHSM(device = device, debug = debug)
        # unlock keystore if our test configuration contains a passphrase
        if HsmPassphrase is not None and HsmPassphrase != "":
            try:
                self.hsm.unlock(password = HsmPassphrase.decode("hex"))
                self.otp_unlock()
            except pyhsm.exception.YHSM_CommandFailed, e:
                # ignore errors from the unlock function, in case our test configuration
                # hasn't been loaded into the YubiHSM yet
                pass

    def tearDown(self):
        # get destructor called properly
        self.hsm = None

    def who_can(self, what, expected = [], extra_khs = []):
        """
        Try the lambda what() with all key handles between 1 and 32, except the expected one.
        Fail on anything but YSM_FUNCTION_DISABLED.
        """
        for kh in list(xrange(1, 32)) + extra_khs:
            if kh in expected:
                continue
            res = None
            try:
                res = what(kh)
                self.fail("Expected YSM_FUNCTION_DISABLED for key handle 0x%0x, got '%s'" % (kh, res))
            except pyhsm.exception.YHSM_CommandFailed, e:
                if e.status != pyhsm.defines.YSM_FUNCTION_DISABLED:
                    self.fail("Expected YSM_FUNCTION_DISABLED for key handle 0x%0x, got %s" \
                                  % (kh, e.status_str))

    def otp_unlock(self):
        """
        Do OTP unlock of the YubiHSM keystore.

        Since we don't always reprogram the YubiHSM, we might need to hunt for an unused OTP.
        """
        if not self.hsm.version.have_unlock():
            return None
        Params = PrimaryAdminYubiKey
        YK = FakeYubiKey(pyhsm.yubikey.modhex_decode(Params[0]).decode('hex'),
                         Params[1].decode('hex'), Params[2].decode('hex')
                         )
        YK.session_ctr = 0
        use_ctr = 1	# the 16 bit power-up counter of the YubiKey
        while use_ctr < 0xffff:
            YK.use_ctr = use_ctr
            otp = YK.from_key()
            try:
                res = self.hsm.unlock(otp = otp)
                self.assertTrue(res)
                # OK - if we got here we've got a successful response for this OTP
                break
            except pyhsm.exception.YHSM_CommandFailed, e:
                if e.status != pyhsm.defines.YSM_OTP_REPLAY:
                    raise
            # don't bother with the session_ctr - test run 5 would mean we first have to
            # exhaust 4 * 256 session_ctr increases before the YubiHSM would pass our OTP
            use_ctr += 1

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
        get your own YubiKey OTP (see function 'from_key').
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
        from Crypto.Cipher import AES
        packed = self.pack()
        obj = AES.new(key, AES.MODE_ECB)
        ciphertext = obj.encrypt(packed)
        return ciphertext

    def from_key(self, public_id, key):
        """
        Return what the YubiKey would have returned when the button was pressed.
        """
        from pyhsm.yubikey import modhex_encode, modhex_decode

        otp = self.get_otp(key)
        from_key = modhex_encode(public_id.encode('hex')) + modhex_encode(otp.encode('hex'))
        return from_key

class YubiKeyRnd(YubiKeyEmu):
    """ YubiKeyEmu with everything but user_id randomized. """

    def __init__(self, user_id):
        timestamp, session_counter, session_use = struct.unpack('IHB', os.urandom(7))
        YubiKeyEmu.__init__(self, user_id, session_counter, timestamp, session_use)

class FakeYubiKey(YubiKeyEmu):
    """
    A complete fake YubiKey.
    """

    def __init__(self, public_id, user_id, key):
        use_ctr, timestamp, session_ctr, = (0, 0, 0,)
        YubiKeyEmu.__init__(self, user_id, use_ctr, timestamp, session_ctr)
        self.public_id = public_id
        self.key = key

    def get_otp(self, key = None):
        if key is None:
            key = self.key
        return YubiKeyEmu.get_otp(self, key)

    def from_key(self):
        return YubiKeyEmu.from_key(self, self.public_id, self.key)
