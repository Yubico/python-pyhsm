"""
implementations of internal DB commands for YubiHSM
"""

# Copyright (c) 2011, Yubico AB
# All rights reserved.

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
    """

    status = None

    def __init__(self, stick, public_id, key_handle, aead):
        self.key_handle = key_handle
        # store padded public_id for comparision in parse_result
        self.public_id = public_id.ljust(pyhsm.defines.YSM_AEAD_NONCE_SIZE, chr(0x0))

        # Check if public_id provided is too long
        if len(self.public_id) != pyhsm.defines.YSM_AEAD_NONCE_SIZE:
            raise pyhsm.exception.YHSM_WrongInputSize(
                'public_id', pyhsm.defines.YSM_AEAD_NONCE_SIZE, len(self.public_id))

        if isinstance(aead, pyhsm.aead_cmd.YHSM_GeneratedAEAD):
            aead = aead.data

        if len(aead) != pyhsm.defines.YUBIKEY_AEAD_SIZE:
            raise pyhsm.exception.YHSM_WrongInputSize(
                'aead', pyhsm.defines.YUBIKEY_AEAD_SIZE, len(aead))

        # typedef struct {
        #   uint8_t publicId[YSM_AEAD_NONCE_SIZE]; // Public id (nonce)
        #   uint32_t keyHandle;                    // Key handle
        #   uint8_t aead[YUBIKEY_AEAD_SIZE];       // AEAD block
        # } YSM_YUBIKEY_AEAD_STORE_REQ;
        fmt = "< %is I %is" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE, pyhsm.defines.YUBIKEY_AEAD_SIZE)
        packed = struct.pack(fmt, self.public_id, self.key_handle, aead)

        YHSM_Cmd.__init__(self, stick, pyhsm.defines.YSM_YUBIKEY_AEAD_STORE, packed)

    def parse_result(self, data):
        """ Return True if the AEAD was stored sucessfully. """
        # typedef struct {
        #   uint8_t publicId[YSM_AEAD_NONCE_SIZE]; // Public id (nonce)
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Validation status
        # } YSM_YUBIKEY_AEAD_STORE_RESP;
        public_id, \
            key_handle, \
            self.status = struct.unpack("< %is I B" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE), data)
        if self.status == pyhsm.defines.YSM_STATUS_OK:
            if public_id != self.public_id:
                raise(pyhsm.exception.YHSM_Error("Unknown public_id in response (got '%s', expected '%s')", \
                                               public_id.encode('hex'), self.public_id.encode('hex')))
            if key_handle != self.key_handle:
                raise(pyhsm.exception.YHSM_Error("Unknown key_handle in response (got '0x%x', expected '0x%x')", \
                                               key_handle, self.key_handle))
            return True
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)

class YHSM_Cmd_DB_Validate_OTP(YHSM_Cmd):
    """
    Request the YubiHSM to validate an OTP for a YubiKey stored
    in the internal database.
    """
    def __init__(self, stick, public_id, otp):
        if len(public_id) > pyhsm.defines.YSM_AEAD_NONCE_SIZE:
            raise pyhsm.exception.YHSM_WrongInputSize(
                'public_id', pyhsm.defines.YSM_AEAD_NONCE_SIZE, len(public_id))
        if len(otp) != pyhsm.defines.OTP_SIZE:
            raise pyhsm.exception.YHSM_WrongInputSize(
                'otp', pyhsm.defines.OTP_SIZE, len(otp))
        # store padded public_id for comparision in parse_result
        self.public_id = public_id.ljust(pyhsm.defines.YSM_AEAD_NONCE_SIZE, chr(0x0))
        self.otp = otp
        self.response = None
        self.status = None
        # typedef struct {
        #   uint8_t publicId[YSM_AEAD_NONCE_SIZE]; // Public id
        #   uint8_t otp[OTP_SIZE];              // OTP
        # } YSM_DB_OTP_VALIDATE_REQ;
        fmt = "%is %is" % (pyhsm.defines.YSM_AEAD_NONCE_SIZE, pyhsm.defines.OTP_SIZE)
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
        #   uint8_t public_id[PUBLIC_ID_SIZE];   // Public id
        #   uint16_t use_ctr;                    // Use counter
        #   uint8_t session_ctr;                 // Session counter
        #   uint8_t tstph;                       // Timestamp (high part)
        #   uint16_t tstpl;                      // Timestamp (low part)
        #   YHSM_STATUS status;                  // Validation status
        # } YHSM_AEAD_OTP_DECODED_RESP;
        fmt = "%is H B B H B" % (pyhsm.defines.PUBLIC_ID_SIZE)
        this_public_id, \
            use_ctr, \
            session_ctr, \
            ts_high, \
            ts_low, \
            self.status = struct.unpack(fmt, data)

        if this_public_id != self.public_id:
            raise pyhsm.exception.YHSM_Error('Bad public_id in response (%s != %s)' %
                                      (this_public_id.encode('hex'), self.public_id.encode('hex')))

        if self.status == pyhsm.defines.YSM_STATUS_OK:
            self.response = pyhsm.validate_cmd.YHSM_ValidationResult( \
                self.public_id, use_ctr, session_ctr, ts_high, ts_low)
            return self.response
        else:
            raise pyhsm.exception.YHSM_CommandFailed(pyhsm.defines.cmd2str(self.command), self.status)
