"""
implementations of secrets/blobs commands for YubiHSM
"""

# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Cmd_Secrets_Generate',
    'YHSM_Cmd_Blob_Generate',
    'YHSM_YubiKeySecrets',
    'YHSM_GeneratedBlob'
]

from cmd import YHSM_Cmd
import exception

class YHSM_Cmd_Secrets_Generate(YHSM_Cmd):
    """
    Ask YubiHSM to generate a secret for a specific public_id

    Generated secret is stored in YubiHSM's internal memory and is
    retreived using YHSM_Cmd_Blob_Generate.
    """
    def __init__(self, stick, public_id):
        # store padded public_id for comparision in parse_result
        self.public_id = public_id.ljust(defines.PUBLIC_ID_SIZE, chr(0x0))
        YHSM_Cmd.__init__(self, stick, defines.YHSM_BUFFER_RANDOM_LOAD, self.public_id)

    def parse_result(self, data):
        """ Return True if the public_id in the response matches the one in the request. """
        return data[1:] == self.public_id


class YHSM_YubiKeySecrets():
    """ Small class to represent a YUBIKEY_SECRETS struct. """
    def __init__(self, key, uid):
        if len(key) != defines.KEY_SIZE:
            raise exception.YHSM_WrongInputSize(
                'key', defines.KEY_SIZE, len(key))

        if type(uid) is not str:
            raise exception.YHSM_WrongInputType(
                'uid', type(''), type(uid))

        self.key = key
        self.uid = uid

    def pack(self):
        """ Return key and uid packed for sending in a command to the YubiHSM. """
        # # 22-bytes Yubikey secrets block
        # typedef struct {
        #   uint8_t key[KEY_SIZE];              // AES key
        #   uint8_t uid[UID_SIZE];              // Unique (secret) ID
        # } YUBIKEY_SECRETS;
        return self.key + self.uid.ljust(defines.YHSM_BLOCK_SIZE, chr(0))

class YHSM_AEAD_Cmd(YHSM_Cmd):
    """
    Class for common non-trivial parse_result for commands returning a
    YSM_AEAD_GENERATE_RESP.
    """
    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: nonce=%s, key_handle=0x%x, status=%s>' % (
                self.__class__.__name__,
                hex(id(self)),
                self.nonce.encode('hex'),
                self.key_handle,
                defines.status2str(self.status)
                )
        else:
            return '<%s instance at %s (not executed)>' % (
                self.__class__.__name__,
                hex(id(self))
                )

    def parse_result(self, data):
        """
        Returns a YHSM_GeneratedBlob instance, or throws exception.YHSM_CommandFailed.
        """
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Status
        #   uint8_t numBytes;                   // Number of bytes in AEAD block
        #   uint8_t aead[YSM_AEAD_MAX_SIZE];    // AEAD block
        # } YSM_AEAD_GENERATE_RESP;

        nonce, \
            key_handle, \
            self.status, \
            num_bytes = struct.unpack_from("< %is I B B" % (defines.YHSM_AEAD_NONCE_SIZE), data, 0)
        if self.status == defines.YHSM_STATUS_OK:
            # struct.hash is not always of size SHA1_HASH_SIZE,
            # it is really the size of numBytes
            aead = data[8:8 + num_bytes]
            self.response = YHSM_GeneratedBlob(nonce, key_handle, aead)
            return self.response
        else:
            raise exception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)

class YHSM_Cmd_AEAD_Buffer_Generate(YHSM_AEAD_Cmd):
    """
    Generate AEAD block of data buffer for a specific key.

    After a key has been loaded into the data buffer, this command can be used
    a number of times to get AEADs of the data buffer for different key handles.

    For example, to encrypt a YubiKey secrets to one or more Yubico KSM's.
    """
    def __init__(self, stick, nonce, key_handle):
        self.nonce = nonce
        self.key_handle = key_handle
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        # } YSM_BUFFER_AEAD_GENERATE_REQ;
        packed = struct.pack("< %is I" % (defines.YHSM_AEAD_NONCE_SIZE), \
                                 self.nonce, self.key_handle)
        YHSM_Cmd.__init__(self, stick, defines.YHSM_BUFFER_AEAD_GENERATE, packed)


class YHSM_GeneratedBlob():
    """ Small class to represent a YHSM_AEAD_GENERATED_RESP. """
    def __init__(self, public_id, key_handle, blob):
        self.public_id = public_id
        self.key_handle = key_handle
        self.blob = blob

    def __repr__(self):
        return '<%s instance at %s: public_id=%s, key_handle=0x%x, blob=%i bytes>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.public_id.encode('hex'),
            self.key_handle,
            len(self.blob)
            )

    def save(self, filename):
        """ Store blob in a file. """
        f = open(filename, "w")
        f.write(self.blob)
        f.close()

    def load(self, filename):
        """ Load blob from a file. """
        f = open(filename, "r")
        self.blob = f.read(defines.YHSM_MAX_KEY_SIZE + defines.YHSM_BLOCK_SIZE)
        f.close()
