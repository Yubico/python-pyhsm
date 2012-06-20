# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import re
import sys
import time
import unittest
import pyhsm
import pyhsm.util

import test_common

from StringIO import StringIO
from test_common import CfgPassphrase, AdminYubiKeys, HsmPassphrase, PrimaryAdminYubiKey

class ConfigureYubiHSMforTest(test_common.YHSM_TestCase):

    def test_aaa_echo(self):
        """ Test echo before reconfiguration. """
        self.assertTrue(self.hsm.echo('test'))

    def test_configure_YHSM(self):
        """
        Reconfiguring YubiHSM for tests.
        """
        self.ser = self.hsm.get_raw_device()

        # get the YubiHSM to exit to configuration mode.
        #self.assertTrue(self.hsm.monitor_exit())
        self.hsm.monitor_exit()

        # get the first prompt without sending anything
        self.config_do("", add_cr = False)

        self.config_do("sysinfo")

        self.config_do("help")

        # clear memory and configure as HSM - has a few prompts we have to get past
        #
        if not self.hsm.version.have_key_store_decrypt():
            self.config_do ("hsm ffffffff\r%s\r%s\ryes" % (CfgPassphrase, HsmPassphrase))
        else:
            # HSM> < hsm ffffffff
            # Enabled flags ffffffff = ...
            # Enter cfg password (g to generate)
            # Enter admin Yubikey public id (enter when done)
            # Enter master key (g to generate) yes
            # Confirm current config being erased (type yes)
            AdminYubiKeysStr = '\r'.join(AdminYubiKeys)
            AdminYubiKeysStr += '\r'
            self.config_do ("hsm ffffffff\r%s\r%s\r%s\ryes" % (CfgPassphrase, AdminYubiKeysStr, HsmPassphrase))

        self.hsm.drain()
        self.add_keys(xrange(31))
        self.hsm.drain()

        self.config_do("keylist")

        if self.hsm.version.have_key_store_decrypt():
            self.config_do("keycommit")

        # load a YubiKey (the first Admin YubiKey) into the internal database
        escape_char = chr(27)
        self.config_do("dbload\r00001,%s,%s,%s,\r" % (PrimaryAdminYubiKey) + escape_char, add_cr = False)

        self.config_do("dblist")

        # get back into HSM mode
        sys.stderr.write("exit")
        self.ser.write("exit\r")

        self.hsm.drain()

        self.hsm.reset()

    def test_zzz_unlock(self):
        """ Test unlock of keystore after reconfiguration. """
        if self.hsm.version.have_unlock():
            Params = PrimaryAdminYubiKey
            YK = test_common.FakeYubiKey(pyhsm.yubikey.modhex_decode(Params[0]).decode('hex'),
                                         Params[1].decode('hex'), Params[2].decode('hex')
                                         )
            # After reconfigure, we know the counter values for PrimaryAdminYubiKey is zero
            # in the internal db. However, the test suite initialization will unlock the keystore
            # (in test_common.YHSM_TestCase.setUp) so a value of 0/1 should result in a replayed OTP.
            YK.use_ctr = 0
            YK.session_ctr = 1
            # first verify counters 1/0 gives the expected YSM_OTP_REPLAY
            try:
                self.hsm.unlock(otp = YK.from_key())
            except pyhsm.exception.YHSM_CommandFailed, e:
                if e.status != pyhsm.defines.YSM_OTP_REPLAY:
                    raise
            # now do real unlock with values 2/1 (there is an extra unlock done somewhere...)
            YK.use_ctr = 2
            self.assertTrue(self.hsm.unlock(password = HsmPassphrase.decode("hex"), otp = YK.from_key()))
        else:
            self.assertTrue(self.hsm.unlock(password = HsmPassphrase.decode("hex")))

    def test_zzz_echo(self):
        """ Test echo after reconfiguration. """
        self.assertTrue(self.hsm.echo('test'))

    def config_do(self, cmd, add_cr = True):
        # Don't have to output command - it is echoed
        #sys.__stderr__.write("> " + cmd + "\n")
        if add_cr:
            self.ser.write(cmd + "\r")
        else:
            self.ser.write(cmd)
        #time.sleep(0.5)
        recv = ''
        fail_count = 0
        sys.stderr.write("< ")
        while True:
            b = self.ser.read(1)
            if not b:
                fail_count += 1
                if fail_count == 5:
                    raise Exception("Did not get the next prompt", recv)
            sys.stderr.write(b)

            recv += b
            lines = recv.split('\n')
            if re.match('^(NO_CFG|WSAPI|HSM).*> .*', lines[-1]):
                break
        return recv

    def add_keys(self, iterator):
        # Set up one key for every available flag
        for num in iterator:
            flags = 1 << num
            key = ("%02x" % (num + 1)) * 32
            self.add_key(flags, num + 1, key)

        # Set up some extra keys with the same key as the flag-keys, but other flags

        # flags YHSM_OTP_BLOB_VALIDATE (0x200) matching key 0x06 (with flags 0x20, YHSM_BLOB_GENERATE)
        flags = 0x200
        key = "06" * 32
        self.add_key(flags, 0x1000, key)

        # Key with full AES ECB capabilities
        # Enabled flags 0000e000 = YHSM_ECB_BLOCK_ENCRYPT,YHSM_ECB_BLOCK_DECRYPT,YHSM_ECB_BLOCK_DECRYPT_CMP
        flags = 0xe000
        key = "1001" * 16
        self.add_key(flags, 0x1001, key)

        # Key allowed to generate AEAD from known data (loaded into buffer), with user specified noncey
        flags = 0x4 | 0x40000000 | 0x20000000
        key = "1002" * 16
        self.add_key(flags, 0x1002, key)

        # Key with everything enabled at once
        flags = 0xffffffff
        key = "2000" * 16
        self.add_key(flags, 0x2000, key)

        # Key with everything enabled at once, and then revoked
        flags = 0xffffffff
        key = "2001" * 16
        self.add_key(flags, 0x2001, key)
        self.config_do("keydis 2001")

        # Key with NIST test vector for HMAC SHA1
        # Enabled flags 00010000 = YSM_HMAC_SHA1_GENERATE
        flags = 0x10000
        key = "303132333435363738393a3b3c3d3e3f40414243".ljust(64, '0')
        self.add_key(flags, 0x3031, key)

        # Key permitting AEAD generate with user specified nonce
        flags = 0x20000002
        key = "20000002" * 8
        self.add_key(flags, 0x20000002, key)

        # Key permitting random AEAD generate with user specified nonce
        flags = 0x20000008
        key = "20000008" * 8
        self.add_key(flags, 0x20000008, key)

    def add_key(self, flags, num, key):
        keyline = "%08x,%s\r" % (num, key)
        self.config_do("flags %04x" % (flags))
        escape_char = chr(27)
        self.config_do("keyload\r" + keyline + escape_char, add_cr = False)
