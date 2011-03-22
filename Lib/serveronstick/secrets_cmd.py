"""
implementations of secrets/blobs commands for Server on Stick
"""

# Copyright (c) 2011, Yubico AB
# All rights reserved.

import struct
import defines

__all__ = [
    # constants
    # functions
    # classes
    'SoS_Cmd_Secrets_Generate',
    'SoS_Cmd_Blob_Generate',
    'SoS_Secrets',
    'SoS_GeneratedBlob'
]

from cmd import SoS_Cmd
import exception

class SoS_Cmd_Secrets_Generate(SoS_Cmd):
    """
    Ask stick to generate a secret for a specific public_id

    Generated secret is stored in stick's internal memory and is
    retreived using SoS_Cmd_Blob_Generate.
    """
    def __init__(self, stick, public_id):
        # store padded public_id for comparision in parse_result
        self.public_id = public_id.ljust(defines.PUBLIC_ID_SIZE, chr(0x0))
        SoS_Cmd.__init__(self, stick, defines.SOS_SECRETS_GENERATE, self.public_id)
        self.response_length = defines.PUBLIC_ID_SIZE + 1

    def parse_result(self, data):
        """ Return True if the public_id in the response matches the one in the request. """
        return data[1:] == self.public_id


class SoS_Cmd_Secrets_Load(SoS_Cmd):
    """
    Ask stick to load a pre-existing secret for a specific public_id.

    This is for importing keys into the HSM system.
    """
    def __init__(self, stick, public_id, secrets):
        # store padded public_id for comparision in parse_result
        self.public_id = public_id.ljust(defines.PUBLIC_ID_SIZE, chr(0x0))
        self.secrets = secrets

        if len(self.public_id) != defines.PUBLIC_ID_SIZE:
            raise exception.SoS_WrongInputSize(
                'public_id', defines.PUBLIC_ID_SIZE, len(self.public_id))

        packed_secrets = secrets.pack()
        if len(packed_secrets) != defines.SOS_BLOCK_SIZE * 2:
            raise exception.SoS_WrongInputSize(
                'secrets.packed()', defines.SOS_BLOCK_SIZE * 2, len(packed_secrets))

        packed = self.public_id + packed_secrets
        SoS_Cmd.__init__(self, stick, defines.SOS_SECRETS_LOAD, packed)
        self.response_length = defines.PUBLIC_ID_SIZE + 1

    def parse_result(self, data):
        """ Return True if the public_id in the response matches the one in the request. """
        return data[1:] == self.public_id


class SoS_Secrets():
    """ Small class to represent a SOS_SECRETS struct. """
    def __init__(self, key, uid):
        if len(key) != defines.KEY_SIZE:
            raise exception.SoS_WrongInputSize(
                'key', defines.KEY_SIZE, len(key))

        if type(uid) is not str:
            raise exception.SoS_WrongInputType(
                'uid', type(''), type(uid))

        self.key = key
        self.uid = uid

    def pack(self):
        """ Return key and uid packed for sending in a command to the SoS. """
        return self.key + self.uid.ljust(defines.SOS_BLOCK_SIZE, chr(0))


class SoS_Cmd_Blob_Generate(SoS_Cmd):
    """
    Request the stick to encrypt the previously generated secret with a
    specific key, and return the resulting blob.
    """
    def __init__(self, stick, key_handle):
        self.public_id = None
        self.key_handle = key_handle
        packed = struct.pack('<I', self.key_handle)
        SoS_Cmd.__init__(self, stick, defines.SOS_BLOB_GENERATE, packed)
        self.response_length = 60

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
        """ Returns a SoS_GeneratedBlob instance, or throws exception.SoS_CommandFailed. """
        # typedef struct {
        #   SOS_SECRETS secrets;            // Blob secrets
        #   uint8_t mac[SOS_BLOCK_SIZE];        // MAC value
        # } SOS_BLOB;
        #
        # typedef uint8_t SOS_STATUS;

        # typedef struct {
        #   uint8_t public_id[PUBLIC_ID_SIZE];   // Public id
        #   uint32_t key_handle;                 // Key handle
        #   SOS_BLOB blob;                      // Blob
        #   SOS_STATUS status;                  // Status
        # } SOS_BLOB_GENERATED_RESP;
        public_id, rest = data[1:defines.PUBLIC_ID_SIZE + 1], data[defines.PUBLIC_ID_SIZE + 1:]
        key_handle = struct.unpack('<I', rest[:4])[0]
        blob = rest[4:-1]
        self.status = ord(rest[-1])
        if self.status == defines.SOS_STATUS_OK:
            self.response = SoS_GeneratedBlob(public_id, key_handle, blob)
            return self.response
        else:
            raise exception.SoS_CommandFailed('SOS_BLOB_GENERATE', self.status)


class SoS_GeneratedBlob():
    """ Small class to represent a SOS_BLOB_GENERATED_RESP. """
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
        self.blob = f.read(defines.BLOB_KEY_SIZE + defines.SOS_BLOCK_SIZE)
        f.close()
