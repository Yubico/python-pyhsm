"""
implementations of internal DB commands for YubiHSM
"""

# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_YubiKey_Store',
]

from cmd import YHSM_Cmd
import exception

class YHSM_Cmd_YubiKey_Store(YHSM_Cmd):
    """
    Ask YubiHSM to store data about a YubiKey in the internal database (not buffer).
    """
    def __init__(self, stick, key_handle, public_id, secrets):
        self.key_handle = key_handle
        # store padded public_id for comparision in parse_result
        self.public_id = public_id.ljust(defines.YSM_AEAD_NONCE_SIZE, chr(0x0))
        self.secrets = secrets

        # Check if public_id provided is too long
        if len(self.public_id) != defines.YSM_AEAD_NONCE_SIZE:
            raise exception.YHSM_WrongInputSize(
                'public_id', defines.YSM_AEAD_NONCE_SIZE, len(self.public_id))

        aead = secrets.pack()
        if len(aead) != defines.YUBIKEY_AEAD_SIZE:
            raise exception.YHSM_WrongInputSize(
                'secrets.packed()', defines.YUBIKEY_AEAD_SIZE, len(aead))

        # typedef struct {
        #   uint8_t publicId[YSM_AEAD_NONCE_SIZE]; // Public id (nonce)
        #   uint32_t keyHandle;                    // Key handle
        #   uint8_t aead[YUBIKEY_AEAD_SIZE];       // AEAD block
        # } YSM_YUBIKEY_AEAD_STORE_REQ;
        packed = struct.pack("< %is I %is" % (defines.YSM_AEAD_NONCE_SIZE, defines.YUBIKEY_AEAD_SIZE), \
                                 self.public_id, \
                                 self.key_handle, \
                                 aead)

        YHSM_Cmd.__init__(self, stick, defines.YSM_YUBIKEY_AEAD_STORE, packed)

    def parse_result(self, data):
        """ Return True if the AEAD was stored sucessfully. """
        # typedef struct {
        #   uint8_t publicId[YSM_AEAD_NONCE_SIZE]; // Public id (nonce)
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Validation status
        # } YSM_YUBIKEY_AEAD_STORE_RESP;
        public_id, \
            key_handle, \
            self.status = struct.unpack("< %is I B" % (defines.YSM_AEAD_NONCE_SIZE), data)
        if self.status == defines.YSM_STATUS_OK:
            if public_id != self.public_id:
                raise(exception.YHSM_Error("Unknown public_id in response (got '%s', expected '%s')", \
                                               public_id.encode('hex'), self.public_id.encode('hex')))
            if key_handle != self.key_handle:
                raise(exception.YHSM_Error("Unknown key_handle in response (got '0x%x', expected '0x%x')", \
                                               key_handle, self.key_handle))
            return True
        else:
            raise exception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)
