"""
Various defines from serveronstick_if.h.
"""
# Copyright (c) 2011, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    'PUBLIC_ID_SIZE',
    'OTP_SIZE',
    'SOS_BLOCK_SIZE',
    'BLOB_KEY_SIZE',
    'UID_SIZE',
    'KEY_SIZE',
    ## statuses
    'SOS_STATUS_OK',
    'SOS_KEY_HANDLE_INVALID',
    'SOS_BLOB_INVALID',
    'SOS_OTP_INVALID',
    'SOS_OTP_REPLAY',
    'SOS_ID_DUPLICATE',
    'SOS_ID_NOT_FOUND',
    'SOS_DB_FULL',
    'SOS_MEMORY_ERROR',
    'SOS_MEMORY_ERROR',
    'SOS_FUNCTION_DISABLED',
    ## commands
    'SOS_NULL',
    'SOS_ECHO',
    'SOS_SYSTEM_INFO_QUERY',
    'SOS_RANDOM_GENERATE',
    # functions
    # classes
]

PUBLIC_ID_SIZE	= 6	# Size of public id for std OTP validation
OTP_SIZE	= 16	# Size of OTP
SOS_BLOCK_SIZE	= 16	# Size of block operations
BLOB_KEY_SIZE	= 32	# Size of blob key

UID_SIZE	= 6	# guessed
KEY_SIZE	= 16

SOS_RESPONSE		= 0x80    # Response bit
SOS_MAX_PKT_SIZE	= 0x60    # Max size of a packet (excluding command byte)

SOS_STATUS_OK           = 0x80    # Executed successfully
SOS_KEY_HANDLE_INVALID  = 0x81    # Key handle is invalid
SOS_BLOB_INVALID        = 0x82    # Supplied blob is invalid
SOS_OTP_INVALID         = 0x83    # Supplied OTP is invalid (CRC or UID)
SOS_OTP_REPLAY          = 0x84    # Supplied OTP is replayed
SOS_ID_DUPLICATE        = 0x85    # The supplied public ID is already in the database
SOS_ID_NOT_FOUND        = 0x86    # The supplied public ID was not found in the database
SOS_DB_FULL             = 0x87    # The database storage is full
SOS_MEMORY_ERROR        = 0x88    # Memory read/write error
SOS_FUNCTION_DISABLED   = 0x89    # Funciton disabled via attribute(s)

SOS_NULL		= 0x00
SOS_ECHO		= 0x01
SOS_SYSTEM_INFO_QUERY	= 0x02
SOS_SECRETS_GENERATE	= 0x03
SOS_SECRETS_LOAD	= 0x04
SOS_BLOB_GENERATE	= 0x05
SOS_OTP_BLOB_VALIDATE	= 0x09

SOS_RANDOM_GENERATE	= 0x0b

