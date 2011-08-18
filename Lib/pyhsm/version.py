"""
module for keeping track of different capabilities in different versions
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'YHSM_Version'
]

class YHSM_Version():
    """ Keeps the YubiHSM's version number and can tell what capabilities it has.

    @ivar sysinfo: Sysinfo when YubiHSM was initialized.
    @type sysinfo: L{YHSM_Cmd_System_Info}
    """

    def __init__(self, sysinfo):
        """
        @param sysinfo: YubiHSM sysinfo.
        @type sysinfo: L{YHSM_Cmd_System_Info}
        """
        self.sysinfo = sysinfo
        self.ver = (sysinfo.version_major, sysinfo.version_minor, sysinfo.version_build,)

    def have_key_storage_unlock(self):
        """
        YSM_KEY_STORAGE_UNLOCK was removed in 1.0.

        The basic concept of a passphrase to unlock the YubiHSM is now provided
        with the more secure YSM_KEY_STORE_DECRYPT.
        """
        return self.ver < (1, 0,)

    def have_key_store_decrypt(self):
        """ YSM_KEY_STORE_DECRYPT was introduced in 1.0, replacing YSM_KEY_STORAGE_UNLOCK. """
        return self.ver > (1, 0,)

    def have_unlock(self):
        """
        YSM_HSM_UNLOCK, featuring YubiKey OTP unlocking of operations,
        was introduced in 1.0.
        """
        return self.ver > (1, 0,)

    def have_keycommit(self):
        """
        YubiHSM have the 'keycommit' command in configuration mode.

        'keycommit' was introduced in 1.0.
        """
        return self.ver > (1, 0,)
