"""
implementations of debugging commands to execute on a YubiHSM

"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_Monitor_Exit',
]

import pyhsm.defines
from pyhsm.cmd import YHSM_Cmd

class YHSM_Cmd_Monitor_Exit(YHSM_Cmd):
    """
    Send magics to YubiHSM in debug mode, and get it to exit to configuration mode again.
    """
    def __init__(self, stick, payload=''):
        #define YHSM_MONITOR_EXIT        0x7f    // Exit to monitor (no response sent)
        #define YHSM_MONITOR_EXIT_MAGIC  0xbaadbeef
        # typedef struct {
        #   uint32_t magic;                     // Magic number for trigger
        #   uint32_t magicInv;                  // 1st complement of magic
        # } YHSM_MONITOR_EXIT_REQ;

        packed = struct.pack('<II', 0xbaadbeef, 0xffffffff - 0xbaadbeef)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_MONITOR_EXIT, packed)
