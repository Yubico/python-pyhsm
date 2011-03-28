"""
Various defines from pyhsm_if.h.
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    'PUBLIC_ID_SIZE',
    'OTP_SIZE',
    'YHSM_BLOCK_SIZE',
    'BLOB_KEY_SIZE',
    'UID_SIZE',
    'KEY_SIZE',
    ## statuses
    'YHSM_STATUS_OK',
    'YHSM_KEY_HANDLE_INVALID',
    'YHSM_BLOB_INVALID',
    'YHSM_OTP_INVALID',
    'YHSM_OTP_REPLAY',
    'YHSM_ID_DUPLICATE',
    'YHSM_ID_NOT_FOUND',
    'YHSM_DB_FULL',
    'YHSM_MEMORY_ERROR',
    'YHSM_MEMORY_ERROR',
    'YHSM_FUNCTION_DISABLED',
    ## commands
    'YHSM_NULL',
    'YHSM_ECHO',
    'YHSM_SYSTEM_INFO_QUERY',
    'YHSM_BUFFER_RANDOM_LOAD',
    'YHSM_BUFFER_LOAD',
    'YHSM_AEAD_GENERATE',
    'YHSM_AEAD_OTP_DECODE',
    'YHSM_RANDOM_GENERATE',
    'YHSM_HMAC_SHA1_GENERATE',
    'YHSM_MONITOR_EXIT',
    ##
    'YHSM_Status2String',
    # functions
    'cmd2str',
    # classes
]

PUBLIC_ID_SIZE	= 6	# Size of public id for std OTP validation
OTP_SIZE	= 16	# Size of OTP
YHSM_BLOCK_SIZE	= 16	# Size of block operations
BLOB_KEY_SIZE	= 32	# Size of blob key

# these two are in ykdef.h
UID_SIZE	= 6
KEY_SIZE	= 16

YHSM_RESPONSE		= 0x80    # Response bit
YHSM_MAX_PKT_SIZE	= 0x60    # Max size of a packet (excluding command byte)

YHSM_STATUS_OK           = 0x80    # Executed successfully
YHSM_KEY_HANDLE_INVALID  = 0x81    # Key handle is invalid
YHSM_AEAD_INVALID        = 0x82    # Supplied AEAD block is invalid
YHSM_OTP_INVALID         = 0x83    # Supplied OTP is invalid (CRC or UID)
YHSM_OTP_REPLAY          = 0x84    # Supplied OTP is replayed
YHSM_ID_DUPLICATE        = 0x85    # The supplied public ID is already in the database
YHSM_ID_NOT_FOUND        = 0x86    # The supplied public ID was not found in the database
YHSM_DB_FULL             = 0x87    # The database storage is full
YHSM_MEMORY_ERROR        = 0x88    # Memory read/write error
YHSM_FUNCTION_DISABLED   = 0x89    # Funciton disabled via attribute(s)
YHSM_KEY_STORAGE_LOCKED  = 0x8a    # Key storage locked
YHSM_MISMATCH            = 0x8b    # Verification mismatch
YSM_INVALID_PARAMETER    = 0x8c    # Invalid parameter

# HMAC flags
YHSM_HMAC_RESET		= 0x01     # Flag to indicate reset at first packet
YHSM_HMAC_FINAL		= 0x02     # Flag to indicate that the hash shall be calculated

# Commands
YHSM_NULL			= 0x00
YHSM_AEAD_OTP_DECODE		= 0x06
YHSM_ECB_BLOCK_ENCRYPT		= 0x0d
YHSM_ECB_BLOCK_DECRYPT		= 0x0e
YHSM_ECB_BLOCK_DECRYPT_CMP	= 0x0f
YHSM_HMAC_SHA1_GENERATE		= 0x10
YHSM_BUFFER_LOAD		= 0x20
YHSM_BUFFER_RANDOM_LOAD		= 0x21
YHSM_ECHO			= 0x23
YHSM_RANDOM_GET			= 0x24
YHSM_SYSTEM_INFO_QUERY		= 0x26
YHSM_MONITOR_EXIT		= 0x7f
YHSM_AEAD_GENERATE	= 0x05


def cmd2str(cmd):
    """ Return command as string. """
    known = {0x00: 'YHSM_NULL',
             0x06: 'YHSM_AEAD_OTP_DECODE',
             0x0d: 'YHSM_ECB_BLOCK_ENCRYPT',
             0x0e: 'YHSM_ECB_BLOCK_DECRYPT',
             0x0f: 'YHSM_ECB_BLOCK_DECRYPT_CMP',
             0x10: 'YHSM_HMAC_SHA1_GENERATE',
             0x20: 'YHSM_BUFFER_LOAD',
             0x21: 'YHSM_BUFFER_RANDOM_LOAD',
             0x23: 'YHSM_ECHO',
             0x24: 'YHSM_RANDOM_GET',
             0x26: 'YHSM_SYSTEM_INFO_QUERY',
             0x7f: 'YHSM_MONITOR_EXIT'
             }
    if cmd in known:
        return known[cmd]
    return "0x02%x" % (cmd)

YHSM_Status2String = {0x80: 'YHSM_STATUS_OK',
                     0x81: 'YHSM_KEY_HANDLE_INVALID',
                     0x82: 'YHSM_BLOB_INVALID',
                     0x83: 'YHSM_OTP_INVALID',
                     0x84: 'YHSM_OTP_REPLAY',
                     0x85: 'YHSM_ID_DUPLICATE',
                     0x86: 'YHSM_ID_NOT_FOUND',
                     0x87: 'YHSM_DB_FULL',
                     0x88: 'YHSM_MEMORY_ERROR',
                     0x89: 'YHSM_FUNCTION_DISABLED',
                     0x8a: 'YHSM_KEY_STORAGE_LOCKED',
                     0x8b: 'YHSM_MISMATCH',
                      0x8c: 'YSM_INVALID_PARAMETER',
                     }
