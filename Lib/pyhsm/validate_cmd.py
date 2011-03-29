"""
implementations of validation commands for YubiHSM
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines
import exception

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_AEAD_Validate_OTP',
]

from cmd import YHSM_Cmd

class YHSM_Cmd_AEAD_Validate_OTP(YHSM_Cmd):
    """
    Request the stick to validate an OTP using an externally stored
    AEAD and a keyhandle to decrypt that AEAD.
    """
    def __init__(self, stick, public_id, otp, key_handle, aead):
        if len(public_id) > defines.PUBLIC_ID_SIZE:
            raise exception.YHSM_WrongInputSize(
                'public_id', defines.PUBLIC_ID_SIZE, len(public_id))
        if len(otp) != defines.OTP_SIZE:
            raise exception.YHSM_WrongInputSize(
                'otp', defines.OTP_SIZE, len(otp))
        if len(aead) != defines.YUBIKEY_AEAD_SIZE:
            raise exception.YHSM_WrongInputSize(
                'aead', defines.YUBIKEY_AEAD_SIZE, len(aead))
        # store padded public_id for comparision in parse_result
        self.public_id = public_id.ljust(defines.PUBLIC_ID_SIZE, chr(0x0))
        self.otp = otp
        self.key_handle = key_handle
        self.response = None
        self.status = None
        # typedef struct {
        #   uint8_t publicId[YSM_AEAD_NONCE_SIZE]; // Public id (nonce)
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t otp[OTP_SIZE];              // OTP
        #   uint8_t aead[YUBIKEY_AEAD_SIZE];    // AEAD block
        # } YSM_AEAD_OTP_DECODE_REQ;
        packed = struct.pack("< %is I %is %is" % (defines.YHSM_AEAD_NONCE_SIZE, \
                                                      defines.OTP_SIZE, \
                                                      defines.YUBIKEY_AEAD_SIZE), \
                                 self.public_id, \
                                 self.key_handle, \
                                 self.otp, \
                                 aead)
        YHSM_Cmd.__init__(self, stick, defines.YHSM_AEAD_OTP_DECODE, packed)

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: public_id=%s, key_handle=0x%x, status=0x%x>' % (
                self.__class__.__name__,
                hex(id(self)),
                self.public_id.encode('hex'),
                self.key_handle,
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
        #   uint32_t keyHandle;                  // Key handle
        #   uint16_t use_ctr;                    // Use counter
        #   uint8_t session_ctr;                 // Session counter
        #   uint8_t tstph;                       // Timestamp (high part)
        #   uint16_t tstpl;                      // Timestamp (low part)
        #   YHSM_STATUS status;                  // Validation status
        # } YHSM_AEAD_OTP_DECODED_RESP;
        this_public_id, \
            key_handle, \
            use_ctr, \
            session_ctr, \
            ts_high, \
            ts_low, \
            self.status = struct.unpack("< %is I H B B H B" % (defines.PUBLIC_ID_SIZE), data)

        if this_public_id != self.public_id:
            raise exception.YHSM_Error('Bad public_id in response (%s != %s)' %
                                      (this_public_id.encode('hex'), self.public_id.encode('hex')))

        if self.status == defines.YHSM_STATUS_OK:
            self.response = YHSM_ValidationResult(self.public_id, use_ctr, session_ctr, ts_high, ts_low)
            return self.response
        else:
            raise exception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)


class YHSM_ValidationResult():
    """
    The result of a Validate operation.

    Contains the counters and timestamps decrypted from the OTP.
    """
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
