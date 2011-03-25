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
    'YHSM_Cmd_Blob_Validate',
]

from cmd import YHSM_Cmd

class YHSM_Cmd_Blob_Validate_OTP(YHSM_Cmd):
    """
    Request the stick to validate an OTP using an externally stored
    blob and a keyhandle to decrypt that blob.
    """
    def __init__(self, stick, public_id, otp, key_handle, blob):
        if len(public_id) > defines.PUBLIC_ID_SIZE:
            raise exception.YHSM_WrongInputSize(
                'public_id', defines.PUBLIC_ID_SIZE, len(public_id))
        if len(otp) != defines.OTP_SIZE:
            raise exception.YHSM_WrongInputSize(
                'otp', defines.OTP_SIZE, len(otp))
        if len(blob) != defines.BLOB_KEY_SIZE + defines.YHSM_BLOCK_SIZE:
            raise exception.YHSM_WrongInputSize(
                'blob', defines.BLOB_KEY_SIZE + defines.YHSM_BLOCK_SIZE, len(blob))

        # store padded public_id for comparision in parse_result
        self.public_id = public_id.ljust(defines.PUBLIC_ID_SIZE, chr(0x0))
        self.otp = otp
        self.key_handle = key_handle
        self.response = None
        self.status = None
        packed = self.public_id + otp + struct.pack('<I', self.key_handle) + blob
        YHSM_Cmd.__init__(self, stick, defines.YHSM_OTP_BLOB_VALIDATE, packed)
        self.response_length = 14

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
        #   uint16_t use_ctr;                    // Use counter
        #   uint8_t session_ctr;                 // Session counter
        #   uint8_t tstph;                                      // Timestamp (high part)
        #   uint16_t tstpl;                                     // Timestamp (low part)
        #   YHSM_STATUS status;                  // Validation status
        # } YHSM_OTP_BLOB_VALIDATED_RESP;
        this_public_id, rest = data[1:defines.PUBLIC_ID_SIZE + 1], data[defines.PUBLIC_ID_SIZE + 1:]
        if this_public_id != self.public_id:
            raise exception.YHSM_Error('Bad public_id in response (%s != %s)' %
                                      (this_public_id.encode('hex'), self.public_id.encode('hex')))

        use_ctr, \
            session_ctr, \
            ts_high, \
            ts_low, \
            self.status = struct.unpack('HBBHB', rest)

        if self.status == defines.YHSM_STATUS_OK:
            self.response = YHSM_ValidationResult(self.public_id, use_ctr, session_ctr, ts_high, ts_low)
            return self.response
        else:
            raise exception.YHSM_CommandFailed('YHSM_OTP_BLOB_VALIDATE', self.status)


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
