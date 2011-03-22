import sys
import time
import unittest
import serveronstick
import serveronstick.util

import test_common

from StringIO import StringIO

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

        # clear memory and configure as HSM - has a few prompts we have to get past
        self.config_do("hsm ffffffff\r\r\ryes")

        self.config_do("sysinfo")

        self.hsm.drain()
        self.add_keys(xrange(31))
        self.hsm.drain()

        self.config_do("keylist")

        # get back into HSM mode
        sys.stderr.write("exit")
        self.ser.write("exit\r")

        self.hsm.drain()

        self.hsm.reset()

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
            if recv.endswith("NO_CFG> "):
                break
            if recv.endswith("HSM> "):
                break
        return recv

    def add_keys(self, iterator):
        for num in iterator:
            flag = 1 << num
            key = ("%02x" % (num + 1)) * 32
            keyline = "%d,%s\r" % (num + 1, key)
            self.config_do("flags %04x" % (flag))
            escape_char = chr(27)
            self.config_do("keyload\r" + keyline + escape_char, add_cr = False)
