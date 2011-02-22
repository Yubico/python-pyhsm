"""
implementations of validation commands for Server on Stick

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
    'SoS_Cmd_Blob_Validate',
]

import cmd
from cmd import SoS_Cmd

class SoS_Cmd_Blob_Validate_OTP(SoS_Cmd):
    """
    Request the stick to validate an OTP using an externally stored
    blob and a keyhandle to decrypt that blob.
    """
    def __init__(self, stick, publicId, otp, keyHandle, blob):
        # store padded publicId for comparision in parse_result
        if len(publicId) > defines.PUBLIC_ID_SIZE:
            raise exception.SoS_WrongInputSize(
                'publicId', defines.PUBLIC_ID_SIZE, len(publicId))
        if len(otp) != defines.OTP_SIZE:
            raise exception.SoS_WrongInputSize(
                'otp', defines.OTP_SIZE, len(otp))
        if len(blob) != defines.BLOB_KEY_SIZE + defines.SOS_BLOCK_SIZE:
            raise exception.SoS_WrongInputSize(
                'blob', defines.BLOB_KEY_SIZE + defines.SOS_BLOCK_SIZE, len(blob))
        self.publicId = publicId.ljust(defines.PUBLIC_ID_SIZE, chr(0x0))
        self.otp = otp
        self.keyHandle = keyHandle
        self.blob = blob
        packed = self.publicId + otp + struct.pack('<I', self.keyHandle) + blob
        SoS_Cmd.__init__(self, stick, defines.SOS_OTP_BLOB_VALIDATE, packed)
        self.response_length = 90

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: publicId=%s, keyHandle=0x%x, useCtr=%i, sessionCtr=%i, status=0x%x>' % (
                self.__class__.__name__,
                hex(id(self)),
                self.publicId.encode('hex'),
                self.keyHandle,
                self.useCtr,
                self.sessionCtr,
                self.status
                )
        else:
            return '<%s instance at %s (not executed)>' % (
                self.__class__.__name__,
                hex(id(self))
                )

    def parse_result(self, data):
        # typedef struct {
        #   uint8_t publicId[PUBLIC_ID_SIZE];   // Public id                                                  
        #   uint16_t useCtr;                    // Use counter                                                
        #   uint8_t sessionCtr;                 // Session counter                                            
        #   uint8_t tstph;                                      // Timestamp (high part)                      
        #   uint16_t tstpl;                                     // Timestamp (low part)                       
        #   SOS_STATUS status;                  // Validation status                                          
        # } SOS_OTP_BLOB_VALIDATED_RESP;
        self.publicId, rest = data[1:defines.PUBLIC_ID_SIZE], data[defines.PUBLIC_ID_SIZE + 1:]
        self.useCtr, \
            self.sessionCtr, \
            self.tstph, \
            self.tstpl, \
            self.status = struct.unpack('HBBHB', rest)
        return self

    pass
