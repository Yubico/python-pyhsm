#!/usr/bin/env python
#
# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.
#
# Utility to send a MONITOR_EXIT command to a YubiHSM.
#
# MONITOR_EXIT only works if the YubiHSM is in debug mode. It would
# be a security problem to allow remote reconfiguration of a production
# YubiHSM.
#
# If your YubiHSM is not in debug mode, enter configuration mode by
# pressing the small button while inserting the YubiHSM in the USB port.
#

import sys
sys.path.append('Lib');
import pyhsm

device = "/dev/ttyACM0"

# simplified arguments parsing
d_argv = dict.fromkeys(sys.argv)
debug = d_argv.has_key('-v')
raw = d_argv.has_key('-v')

if d_argv.has_key('-h'):
    sys.stderr.write("Syntax: %s [-v] [-R]\n" % (sys.argv[0]))
    sys.stderr.write("\nOptions :\n")
    sys.stderr.write("  -v  verbose\n")
    sys.stderr.write("  -R  raw MONITOR_EXIT command\n")
    sys.exit(0)

res = 0
try:
    s = pyhsm.base.YHSM(device=device, debug = debug)

    if raw:
        # No initialization
        s.write('\x7f\xef\xbe\xad\xba\x10\x41\x52\x45')
    else:
        print "Version: %s" % s.info()
        s.monitor_exit()

    print "Exited monitor-mode (maybe)"

    if raw:
        print "s.stick == %s" % s.stick
        print "s.stick.ser == %s" % s.stick.ser

        for _ in xrange(3):
            s.stick.ser.write("\n")
            line = s.stick.ser.readline()
            print "%s" % (line)
except pyhsm.exception.YHSM_Error, e:
    print "ERROR: %s" % e
    res = 1

sys.exit(res)
