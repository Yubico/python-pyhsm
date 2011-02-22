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
]

import cmd
from cmd import SoS_Cmd

class SoS_Cmd_Secrets_Generate(SoS_Cmd):
    """
    Ask stick to generate a secret for a specific publicId.
    
    Generated secret is stored in stick's internal memory and is
    retreived using SoS_Cmd_Blob_Generate.
    """
    def __init__(self, stick, publicId):
        # store padded publicId for comparision in parse_result
        self.publicId = publicId.ljust(defines.PUBLIC_ID_SIZE, chr(0x0))
        SoS_Cmd.__init__(self, stick, cmd.SOS_SECRETS_GENERATE, self.publicId)
        self.response_length = defines.PUBLIC_ID_SIZE + 1

    def parse_result(self, data):
        return data[1:] == self.publicId

    pass

class SoS_Cmd_Secrets_Load(SoS_Cmd):
    """
    Ask stick to load a pre-existing secret for a specific publicId.
    
    This is for importing keys into the HSM system.
    """
    def __init__(self, stick, publicId, secrets):
        if len(secrets) != defines.SOS_BLOCK_SIZE * 2:
            assert()
        # store padded publicId for comparision in parse_result
        self.publicId = publicId.ljust(defines.PUBLIC_ID_SIZE, chr(0x0))
        self.secrets = secrets
        packed = self.publicId + secrets
        SoS_Cmd.__init__(self, stick, cmd.SOS_SECRETS_LOAD, packed)
        self.response_length = defines.PUBLIC_ID_SIZE + 1

    def parse_result(self, data):
        return data[1:] == self.publicId

    pass

class SoS_Cmd_Blob_Generate(SoS_Cmd):
    """
    Request the stick to encrypt the previously generated secret with a
    specific key, and return the resulting blob.
    """
    def __init__(self, stick, keyHandle):
        self.keyHandle = keyHandle
        packed = struct.pack('<I', self.keyHandle)
        SoS_Cmd.__init__(self, stick, cmd.SOS_BLOB_GENERATE, packed)
        self.response_length = 60

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: publicId=%s, keyHandle=0x%x, status=0x%x>' % (
                self.__class__.__name__,
                hex(id(self)),
                self.publicId.encode('hex'),
                self.keyHandle,
                self.status
                )
        else:
            return '<%s instance at %s (not executed)>' % (
                self.__class__.__name__,
                hex(id(self))
                )

    def parse_result(self, data):
        # typedef struct {
        #   SOS_SECRETS_EXT secrets;            // Blob secrets                                              
        #   uint8_t mac[SOS_BLOCK_SIZE];        // MAC value                                                 
        # } SOS_BLOB_EXT;
        #
        # typedef uint8_t SOS_STATUS;

        # typedef struct {
        #   uint8_t publicId[PUBLIC_ID_SIZE];   // Public id                                                 
        #   uint32_t keyHandle;                 // Key handle                                                
        #   SOS_BLOB blob;                      // Blob                                                      
        #   SOS_STATUS status;                  // Status                                                    
        # } SOS_BLOB_GENERATED_RESP;
        # XXX BUGFIX IN STICK REQUIRED, publicId and keyHandle are crossed
        self.publicId, rest = data[1:defines.PUBLIC_ID_SIZE], data[defines.PUBLIC_ID_SIZE + 1:]
        self.keyHandle = struct.unpack('<I', rest[:4])[0]
        self.blob = rest[4:-1]
        self.status = ord(rest[-1])
        return self

    pass
