# Copyright (c) 2011-2014 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
"""
the pyhsm package

Basic usage ::

  import pyhsm

  try:
      hsm = pyhsm.base.YHSM(device="/dev/ttyACM0", debug=False)
      print "Version : %s" % (hsm.info())
  except pyhsm.exception.YHSM_Error, e:
      print "ERROR: %s" % e

See help(pyhsm.base) (L{pyhsm.base.YHSM}) for more information.
"""

__version__ = '1.0.4k'
__copyright__ = 'Yubico AB'
__organization__ = 'Yubico'
__license__ = 'BSD'
__authors__ = ['Fredrik Thulin', 'Dain Nilsson']

__all__ = ["base",
           "cmd",
           "defines",
           "exception",
           "stick",
           "util",
           "version",
           "yubikey",
           "soft_hsm",
           #
           "aead_cmd",
           "aes_ecb_cmd",
           "basic_cmd",
           "buffer_cmd",
           "db_cmd",
           "debug_cmd",
           "hmac_cmd",
           "oath_hotp",
           "validate_cmd",
           ]

from pyhsm.base import YHSM
