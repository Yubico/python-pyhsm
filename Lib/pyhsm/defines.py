"""
Various defines from pyhsm_if.h.
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    'YSM_PUBLIC_ID_SIZE',
    'YSM_OTP_SIZE',
    'YSM_BLOCK_SIZE',
    'YSM_MAX_KEY_SIZE',
    'YSM_DATA_BUF_SIZE',
    'YSM_AEAD_NONCE_SIZE',
    'YSM_AEAD_MAC_SIZE',
    'YSM_CCM_CTR_SIZE',
    'YSM_AEAD_MAX_SIZE',
    'YSM_SHA1_HASH_SIZE',
    'YSM_CTR_DRBG_SEED_SIZE',
    'YSM_MAX_PKT_SIZE',
    'YSM_PROTOCOL_VERSION',
    'YSM_TEMP_KEY_HANDLE',
    'UID_SIZE',
    'KEY_SIZE',
    ## statuses
    'YSM_STATUS_OK',
    'YSM_KEY_HANDLE_INVALID',
    'YSM_AEAD_INVALID',
    'YSM_OTP_INVALID',
    'YSM_OTP_REPLAY',
    'YSM_ID_DUPLICATE',
    'YSM_ID_NOT_FOUND',
    'YSM_DB_FULL',
    'YSM_MEMORY_ERROR',
    'YSM_FUNCTION_DISABLED',
    'YSM_KEY_STORAGE_LOCKED',
    'YSM_MISMATCH',
    'YSM_INVALID_PARAMETER',
    ## commands
    'YSM_NULL',
    'YSM_AEAD_GENERATE',
    'YSM_BUFFER_AEAD_GENERATE',
    'YSM_RANDOM_AEAD_GENERATE',
    'YSM_AEAD_DECRYPT_CMP',
    'YSM_DB_YUBIKEY_AEAD_STORE',
    'YSM_DB_YUBIKEY_AEAD_STORE2',
    'YSM_AEAD_YUBIKEY_OTP_DECODE',
    'YSM_DB_OTP_VALIDATE',
    'YSM_AES_ECB_BLOCK_ENCRYPT',
    'YSM_AES_ECB_BLOCK_DECRYPT',
    'YSM_AES_ECB_BLOCK_DECRYPT_CMP',
    'YSM_HMAC_SHA1_GENERATE',
    'YSM_TEMP_KEY_LOAD',
    'YSM_BUFFER_LOAD',
    'YSM_BUFFER_RANDOM_LOAD',
    'YSM_NONCE_GET',
    'YSM_ECHO',
    'YSM_RANDOM_GENERATE',
    'YSM_RANDOM_RESEED',
    'YSM_SYSTEM_INFO_QUERY',
    'YSM_MONITOR_EXIT',
    ##
    # functions
    'cmd2str',
    'status2str'
    # classes
]

YSM_PUBLIC_ID_SIZE	= 6	# Size of public id for std OTP validation
YSM_OTP_SIZE		= 16	# Size of OTP
YSM_BLOCK_SIZE		= 16	# Size of block operations
YSM_MAX_KEY_SIZE	= 32	# Max size of CCMkey
YSM_DATA_BUF_SIZE	= 64	# Size of internal data buffer
YSM_AEAD_NONCE_SIZE	= 6	# Size of AEAD nonce (excluding size of key handle)
YSM_AEAD_MAC_SIZE	= 8	# Size of AEAD MAC field
YSM_CCM_CTR_SIZE	= 2	# Sizeof of AES CCM counter field
YSM_AEAD_MAX_SIZE	= (YSM_DATA_BUF_SIZE + YSM_AEAD_MAC_SIZE) # Max size of an AEAD block
YSM_SHA1_HASH_SIZE	= 20	# 160-bit SHA1 hash size
YSM_CTR_DRBG_SEED_SIZE	= 32	# Size of CTR-DRBG entropy
YSM_MAX_PKT_SIZE	= 0x60  # Max size of a packet (excluding command byte)
YSM_PROTOCOL_VERSION	= 1	# Protocol version for this file


YSM_TEMP_KEY_HANDLE	= 0xffffffff # Phantom temporary key handle

# these two are in ykdef.h
UID_SIZE	= 6
KEY_SIZE	= 16

YSM_RESPONSE		= 0x80    # Response bit
YSM_YUBIKEY_AEAD_SIZE	= (KEY_SIZE + UID_SIZE + YSM_AEAD_MAC_SIZE)

# Response codes
YSM_STATUS_OK           = 0x80    # Executed successfully
YSM_KEY_HANDLE_INVALID  = 0x81    # Key handle is invalid
YSM_AEAD_INVALID        = 0x82    # Supplied AEAD block is invalid
YSM_OTP_INVALID         = 0x83    # Supplied OTP is invalid (CRC or UID)
YSM_OTP_REPLAY          = 0x84    # Supplied OTP is replayed
YSM_ID_DUPLICATE        = 0x85    # The supplied public ID is already in the database
YSM_ID_NOT_FOUND        = 0x86    # The supplied public ID was not found in the database
YSM_DB_FULL             = 0x87    # The database storage is full
YSM_MEMORY_ERROR        = 0x88    # Memory read/write error
YSM_FUNCTION_DISABLED   = 0x89    # Funciton disabled via attribute(s)
YSM_KEY_STORAGE_LOCKED  = 0x8a    # Key storage locked
YSM_MISMATCH            = 0x8b    # Verification mismatch
YSM_INVALID_PARAMETER   = 0x8c    # Invalid parameter

def status2str(num):
    """ Return YubiHSM response status code as string. """
    known = {0x80: 'YSM_STATUS_OK',
             0x81: 'YSM_KEY_HANDLE_INVALID',
             0x82: 'YSM_AEAD_INVALID',
             0x83: 'YSM_OTP_INVALID',
             0x84: 'YSM_OTP_REPLAY',
             0x85: 'YSM_ID_DUPLICATE',
             0x86: 'YSM_ID_NOT_FOUND',
             0x87: 'YSM_DB_FULL',
             0x88: 'YSM_MEMORY_ERROR',
             0x89: 'YSM_FUNCTION_DISABLED',
             0x8a: 'YSM_KEY_STORAGE_LOCKED',
             0x8b: 'YSM_MISMATCH',
             0x8c: 'YSM_INVALID_PARAMETER',
             }

    if num in known:
        return known[num]
    return "0x%02x" % (num)

# HMAC flags
YSM_HMAC_SHA1_RESET		= 0x01     # Flag to indicate reset at first packet
YSM_HMAC_SHA1_FINAL		= 0x02     # Flag to indicate that the hash shall be calculated
YSM_HMAC_SHA1_TO_BUFFER	= 0x04     # Flag to transfer HMAC to buffer

# Commands
YSM_NULL			= 0x00
YSM_AEAD_GENERATE		= 0x01
YSM_BUFFER_AEAD_GENERATE	= 0x02
YSM_RANDOM_AEAD_GENERATE	= 0x03
YSM_AEAD_DECRYPT_CMP		= 0x04
YSM_DB_YUBIKEY_AEAD_STORE	= 0x05
YSM_AEAD_YUBIKEY_OTP_DECODE	= 0x06
YSM_DB_OTP_VALIDATE		= 0x07
YSM_DB_YUBIKEY_AEAD_STORE2	= 0x08
YSM_AES_ECB_BLOCK_ENCRYPT	= 0x0d
YSM_AES_ECB_BLOCK_DECRYPT	= 0x0e
YSM_AES_ECB_BLOCK_DECRYPT_CMP	= 0x0f
YSM_HMAC_SHA1_GENERATE		= 0x10
YSM_TEMP_KEY_LOAD		= 0x11
YSM_BUFFER_LOAD			= 0x20
YSM_BUFFER_RANDOM_LOAD		= 0x21
YSM_NONCE_GET			= 0x22
YSM_ECHO			= 0x23
YSM_RANDOM_GENERATE		= 0x24
YSM_RANDOM_RESEED		= 0x25
YSM_SYSTEM_INFO_QUERY		= 0x26
YSM_KEY_STORAGE_UNLOCK		= 0x27	# Deprecated in 1.0
YSM_HSM_UNLOCK			= 0x28
YSM_KEY_STORE_DECRYPT		= 0x29
YSM_MONITOR_EXIT		= 0x7f

def cmd2str(cmd):
    """ Return command as string. """
    known = {0x00: 'YSM_NULL',
             0x01: 'YSM_AEAD_GENERATE',
             0x02: 'YSM_BUFFER_AEAD_GENERATE',
             0x03: 'YSM_RANDOM_AEAD_GENERATE',
             0x04: 'YSM_AEAD_DECRYPT_CMP',
             0x05: 'YSM_DB_YUBIKEY_AEAD_STORE',
             0x06: 'YSM_AEAD_YUBIKEY_OTP_DECODE',
             0x07: 'YSM_DB_OTP_VALIDATE',
             0x08: 'YSM_DB_YUBIKEY_AEAD_STORE2',
             0x0d: 'YSM_AES_ECB_BLOCK_ENCRYPT',
             0x0e: 'YSM_AES_ECB_BLOCK_DECRYPT',
             0x0f: 'YSM_AES_ECB_BLOCK_DECRYPT_CMP',
             0x10: 'YSM_HMAC_SHA1_GENERATE',
             0x11: 'YSM_TEMP_KEY_LOAD',
             0x20: 'YSM_BUFFER_LOAD',
             0x21: 'YSM_BUFFER_RANDOM_LOAD',
             0x22: 'YSM_NONCE_GET',
             0x23: 'YSM_ECHO',
             0x24: 'YSM_RANDOM_GENERATE',
             0x25: 'YSM_RANDOM_RESEED',
             0x26: 'YSM_SYSTEM_INFO_QUERY',
             0x27: 'YSM_KEY_STORAGE_UNLOCK',
             0x28: 'YSM_HSM_UNLOCK',
             0x29: 'YSM_KEY_STORE_DECRYPT',
             0x7f: 'YSM_MONITOR_EXIT',
             }
    if cmd in known:
        return known[cmd]
    return "0x%02x" % (cmd)
