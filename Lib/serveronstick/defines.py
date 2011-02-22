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
    # functions
    # classes
]

PUBLIC_ID_SIZE	= 6	# Size of public id for std OTP validation
OTP_SIZE	= 16	# Size of OTP
SOS_BLOCK_SIZE	= 16	# Size of block operations
BLOB_KEY_SIZE	= 32	# Size of blob key

UID_SIZE	= 6	# guessed
KEY_SIZE	= 16
