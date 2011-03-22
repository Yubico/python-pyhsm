import sys
import unittest
import serveronstick

import test_common

class TestOtpValidate(test_common.YHSM_TestCase):

    def setUp(self):
        self.hsm = serveronstick.base.SoS(device = "/dev/ttyACM0", debug = True)

        # Check that this is a device we know how to talk to
        assert(self.hsm.info().protocolVersion == 1)

    def test_load_secret_wrong_key(self):
        """ Test load_secret with key that should not be allowed to. """
        key = "A" * 16
        uid = '\x4d\x4d\x4d\x4d\x4d\x4d'
        public_id = 'f0f1f2f3f4f5'.decode('hex')
        # Enabled flags 00000100 = SOS_BLOB_STORE
        # HSM> < keyload - Load key data now using flags 00000100. Press ESC to quit
        # 00000009 - stored ok
        key_handle = 9	# Enabled flags 00000020 = SOS_BLOB_GENERATE

        secret = serveronstick.secrets_cmd.SoS_Secrets(key, uid)
        self.hsm.load_secret(public_id, secret)

        try:
            self.hsm.generate_blob(key_handle)
            self.fail("key handle should not be valid for generate_blob")
        except serveronstick.exception.SoS_CommandFailed, e:
            self.assertEquals(e.status_str, 'SOS_FUNCTION_DISABLED')

    def test_load_secret(self):
        """ Test load_secret. """
        key = "A" * 16
        uid = '\x4d\x01\x4d\x02'
        public_id = 'f1f2f3f4f5f6'.decode('hex')
        # Enabled flags 00000020 = SOS_BLOB_GENERATE
        # HSM> < keyload - Load key data now using flags 00000020. Press ESC to quit
        # 00000006 - stored ok
        key_handle = 6

        secret = serveronstick.secrets_cmd.SoS_Secrets(key, uid)
        self.hsm.load_secret(public_id, secret)

        blob = self.hsm.generate_blob(key_handle)

        #self.assertIsInstance(blob, serveronstick.secrets_cmd.SoS_GeneratedBlob)
        self.assertTrue(isinstance(blob, serveronstick.secrets_cmd.SoS_GeneratedBlob))

        self.assertEqual(blob.public_id, public_id)
        self.assertEqual(blob.key_handle, key_handle)
        self.assertEqual(blob.blob.encode('hex'),
                         '45bbdf26fc1a5560b6ff119dfdf743dbd1a65e3a00eab569'
                         'fe27b5c3705ea4e8e2db0a88c21124e15321976154e4703f'
                         )
