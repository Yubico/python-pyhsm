"""
implementations of internal DB commands for YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_DB_YubiKey_Store',
    'YHSM_Cmd_DB_Validate_OTP',
]

import pyhsm.defines
import pyhsm.exception
import pyhsm.aead_cmd
import pyhsm.validate_cmd
from pyhsm.cmd import YHSM_Cmd

class YHSM_Cmd_DB_YubiKey_Store(YHSM_Cmd):
    """
    Ask YubiHSM to store data about a YubiKey in the internal database (not buffer).

    The input is an AEAD, perhaps previously created using generate_aead().

    If the nonce for the AEAD is not the same as the public_id, specify it with the nonce keyword argument.
    This requires a YubiHSM >= 1.0.4.
    """

    status = None

    def __init__(self, stick, public_id, key_handle, aead, nonce = None):
        self.key_handle = pyhsm.util.input_validate_key_handle(key_handle)
        self.public_id = pyhsm.util.input_validate_nonce(public_id, pad = True)
        aead = pyhsm.util.input_validate_aead(aead, expected_len = pyhsm.defines.YSM_YUBIKEY_AEAD_SIZE)
        if nonce is None:
            # typedef struct {
            #   uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id (nonce)
            #   uint32_t keyHandle;                    // Key handle
            #   uint8_t aead[YSM_YUBIKEY_AEAD_SIZE];       // AEAD block
            # } YSM_DB_YUBIKEY_AEAD_STORE_REQ;
            fmt = "< %is I %is" % (pyhsm.defines.YSM_PUBLIC_ID_SIZE, \
                                       pyhsm.defines.YSM_YUBIKEY_AEAD_SIZE)
            packed = struct.pack(fmt, self.public_id, self.key_handle, aead)
            YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_DB_YUBIKEY_AEAD_STORE, packed)
        else:
            nonce = pyhsm.util.input_validate_nonce(nonce)
            # typedef struct {
            #   uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id
            #   uint32_t keyHandle;                    // Key handle
            #   uint8_t aead[YSM_YUBIKEY_AEAD_SIZE];       // AEAD block
            #   uint8_t nonce[YSM_AEAD_NONCE_SIZE];  // Nonce
            # } YSM_DB_YUBIKEY_AEAD_STORE2_REQ;
            fmt = "< %is I %is %is" % (pyhsm.defines.YSM_PUBLIC_ID_SIZE, \
                                           pyhsm.defines.YSM_YUBIKEY_AEAD_SIZE, \
                                           pyhsm.defines.YSM_AEAD_NONCE_SIZE)
            packed = struct.pack(fmt, self.public_id, self.key_handle, aead, nonce)
            YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_DB_YUBIKEY_AEAD_STORE2, packed)

    def parse_result(self, data):
        """ Return True if the AEAD was stored sucessfully. """
        # typedef struct {
        #   uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id (nonce)
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Validation status
        # } YSM_DB_YUBIKEY_AEAD_STORE_RESP;
        public_id, \
            key_handle, \
            self.status = struct.unpack("< %is I B" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE), data)

        pyhsm.util.validate_cmd_response_str('public_id', public_id, self.public_id)
        pyhsm.util.validate_cmd_response_hex('key_handle', key_handle, self.key_handle)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            return True
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)

class YHSM_Cmd_DB_Validate_OTP(YHSM_Cmd):
    """
    Request the YubiHSM to validate an OTP for a YubiKey stored
    in the internal database.
    """

    response = None
    status = None

    def __init__(self, stick, public_id, otp):
        self.public_id = pyhsm.util.input_validate_nonce(public_id, pad = True)
        self.otp = pyhsm.util.input_validate_str(otp, 'otp', exact_len = pyhsm.defines.YSM_OTP_SIZE)
        # typedef struct {
        #   uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id
        #   uint8_t otp[YSM_OTP_SIZE];              // OTP
        # } YSM_DB_OTP_VALIDATE_REQ;
        fmt = "%is %is" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE, pyhsm.defines.YSM_OTP_SIZE)
        packed = struct.pack(fmt, self.public_id, self.otp)
        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_DB_OTP_VALIDATE, packed)

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: public_id=%s, status=0x%x>' % (
                self.__class__.__name__,
                hex(id(self)),
                self.public_id.encode('hex'),
                self.status
                )
        else:
            return '<%s instance at %s (not executed)>' % (
                self.__class__.__name__,
                hex(id(self))
                )

    def parse_result(self, data):
        # typedef struct {
        #   uint8_t public_id[YSM_PUBLIC_ID_SIZE];   // Public id
        #   uint16_t use_ctr;                    // Use counter
        #   uint8_t session_ctr;                 // Session counter
        #   uint8_t tstph;                       // Timestamp (high part)
        #   uint16_t tstpl;                      // Timestamp (low part)
        #   YHSM_STATUS status;                  // Validation status
        # } YHSM_AEAD_OTP_DECODED_RESP;
        fmt = "%is H B B H B" % (pyhsm.defines.YSM_PUBLIC_ID_SIZE)
        public_id, \
            use_ctr, \
            session_ctr, \
            ts_high, \
            ts_low, \
            self.status = struct.unpack(fmt, data)

        pyhsm.util.validate_cmd_response_str('public_id', public_id, self.public_id)

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            self.response = pyhsm.validate_cmd.YHSM_ValidationResult( \
                public_id, use_ctr, session_ctr, ts_high, ts_low)
            return self.response
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)
