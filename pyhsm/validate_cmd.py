"""
implementations of validation commands for YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_AEAD_Validate_OTP',
    'YHSM_ValidationResult',
]

import pyhsm.defines
import pyhsm.exception
from pyhsm.aead_cmd import YHSM_AEAD_Cmd

class YHSM_Cmd_AEAD_Validate_OTP(YHSM_AEAD_Cmd):
    """
    Request the YubiHSM to validate an OTP using an externally stored AEAD.
    """

    response = None
    status = None

    def __init__(self, stick, public_id, otp, key_handle, aead):
        self.public_id = pyhsm.util.input_validate_nonce(public_id, pad = True)
        self.otp = pyhsm.util.input_validate_str(otp, 'otp', exact_len = pyhsm.defines.YSM_OTP_SIZE)
        self.key_handle = pyhsm.util.input_validate_key_handle(key_handle)
        aead = pyhsm.util.input_validate_aead(aead, expected_len = pyhsm.defines.YSM_YUBIKEY_AEAD_SIZE)
        # typedef struct {
        #   uint8_t publicId[YSM_PUBLIC_ID_SIZE];   // Public id (nonce)
        #   uint32_t keyHandle;                     // Key handle
        #   uint8_t otp[YSM_OTP_SIZE];              // OTP
        #   uint8_t aead[YSM_YUBIKEY_AEAD_SIZE];    // AEAD block
        # } YSM_AEAD_YUBIKEY_OTP_DECODE_REQ;
        fmt = "< %is I %is %is" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE, \
                                       pyhsm.defines.YSM_OTP_SIZE, \
                                       pyhsm.defines.YSM_YUBIKEY_AEAD_SIZE)
        packed = struct.pack(fmt, self.public_id, \
                                 self.key_handle, \
                                 self.otp, \
                                 aead)
        YHSM_AEAD_Cmd.__init__(self, stick, pyhsm.defines.YSM_AEAD_YUBIKEY_OTP_DECODE, packed)

    def parse_result(self, data):
        # typedef struct {
        #   uint8_t public_id[YSM_PUBLIC_ID_SIZE];   // Public id
        #   uint32_t keyHandle;                  // Key handle
        #   uint16_t use_ctr;                    // Use counter
        #   uint8_t session_ctr;                 // Session counter
        #   uint8_t tstph;                       // Timestamp (high part)
        #   uint16_t tstpl;                      // Timestamp (low part)
        #   YHSM_STATUS status;                  // Validation status
        # } YHSM_AEAD_OTP_DECODED_RESP;
        fmt = "< %is I H B B H B" % (pyhsm.defines.YSM_PUBLIC_ID_SIZE)
        public_id, \
            key_handle, \
            use_ctr, \
            session_ctr, \
            ts_high, \
            ts_low, \
            self.status = struct.unpack(fmt, data)

        pyhsm.util.validate_cmd_response_str('public_id', public_id, self.public_id)
        pyhsm.util.validate_cmd_response_hex('key_handle', key_handle, self.key_handle)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            self.response = YHSM_ValidationResult(self.public_id, use_ctr, session_ctr, ts_high, ts_low)
            return self.response
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)


class YHSM_ValidationResult():
    """
    The result of a Validate operation.

    Contains the counters and timestamps decrypted from the OTP.

    @ivar public_id: The six bytes public ID of the YubiKey that produced the OTP
    @ivar use_ctr: The 16-bit power-on non-volatile counter of the YubiKey
    @ivar session_ctr: The 8-bit volatile session counter of the YubiKey
    @ivar ts_high: The high 8 bits of the 24-bit 8 hz timer since power-on of the YubiKey
    @ivar ts_low: The low 16 bits of the 24-bit 8 hz timer since power-on of the YubiKey
    @type public_id: string
    @type use_ctr: integer
    @type session_ctr: integer
    @type ts_high: integer
    @type ts_low: integer
    """

    public_id = use_ctr = session_ctr = ts_high = ts_low = None

    def __init__(self, public_id, use_ctr, session_ctr, ts_high, ts_low):
        self.public_id = public_id
        self.use_ctr = use_ctr
        self.session_ctr = session_ctr
        self.ts_high = ts_high
        self.ts_low = ts_low

    def __repr__(self):
        return '<%s instance at %s: public_id=%s, use_ctr=%i, session_ctr=%i, ts=%i/%i>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.public_id.encode('hex'),
            self.use_ctr,
            self.session_ctr,
            self.ts_high,
            self.ts_low
            )
