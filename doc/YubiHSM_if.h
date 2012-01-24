/*************************************************************************
**                                                                      **
**      YubiHSM_if - HSM mode interface declarations                    **
**                                                                      **
**      Copyright 2011 - Yubico AB                                      **
**                                                                      **
**      Date   / Sig / Rev  / History                                   **
**      110205 / J E / 0.00 / Main                                      **
**      110412 / J E / 0.98 / Release changes                           **
**      110809 / J E / 1.01 / Release changes                           **
**                                                                      **
*************************************************************************/

#ifndef __YUBIHSM_H_INCLUDED
#define __YUBIHSM_H_INCLUDED

#include <ykdef.h>

#ifdef _WIN32
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
#endif

#define YSM_PUBLIC_ID_SIZE      6       // Size of public id for std OTP validation
#define YSM_OTP_SIZE            16      // Size of OTP
#define YSM_BLOCK_SIZE          16      // Size of block operations
#define YSM_MAX_KEY_SIZE        32      // Max size of CCMkey
#define YSM_DATA_BUF_SIZE       64      // Size of internal data buffer
#define YSM_AEAD_NONCE_SIZE     6       // Size of AEAD nonce (excluding size of key handle)
#define YSM_AEAD_MAC_SIZE       8       // Size of AEAD MAC field
#define YSM_CCM_CTR_SIZE        2       // Sizeof of AES CCM counter field
#define YSM_AEAD_MAX_SIZE       (YSM_DATA_BUF_SIZE + YSM_AEAD_MAC_SIZE) // Max size of an AEAD block
#define YSM_YUBIKEY_AEAD_SIZE   (KEY_SIZE + UID_SIZE + YSM_AEAD_MAC_SIZE)
#define YSM_SHA1_HASH_SIZE      20      // 160-bit SHA1 hash size
#define YSM_CTR_DRBG_SEED_SIZE  32      // Size of CTR-DRBG entropy
#define YSM_MAX_PKT_SIZE        0x60    // Max size of a packet (excluding command byte)
#define YSM_PROTOCOL_VERSION    1       // Protocol version for this file

#define YSM_TEMP_KEY_HANDLE     0xffffffff  // Phantom temporary key handle

// 22-bytes Yubikey secrets block

typedef struct {
    uint8_t key[KEY_SIZE];              // AES key
    uint8_t uid[UID_SIZE];              // Unique (secret) ID
} YSM_YUBIKEY_SECRETS;

// AES CCM nonce

typedef struct {
    uint32_t keyHandle;                 // Key handle
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce / public id
} YSM_CCM_NONCE;

// Up- and downlink packet

typedef struct {
    uint8_t bcnt;                       // Number of bytes (cmd + payload)
    uint8_t cmd;                        // YSM_xxx command
    uint8_t payload[YSM_MAX_PKT_SIZE];  // Payload
} YSM_PKT;

// HSM commands

#define YSM_RESPONSE            0x80    // Response bit

// Status codes

typedef uint8_t YSM_STATUS;

#define YSM_STATUS_OK           0x80    // Executed successfully
#define YSM_KEY_HANDLE_INVALID  0x81    // Key handle is invalid
#define YSM_AEAD_INVALID        0x82    // Supplied AEAD block is invalid
#define YSM_OTP_INVALID         0x83    // Supplied OTP is invalid (CRC or UID)
#define YSM_OTP_REPLAY          0x84    // Supplied OTP is replayed
#define YSM_ID_DUPLICATE        0x85    // The supplied public ID is already in the database
#define YSM_ID_NOT_FOUND        0x86    // The supplied public ID was not found in the database
#define YSM_DB_FULL             0x87    // The database storage is full
#define YSM_MEMORY_ERROR        0x88    // Memory read/write error
#define YSM_FUNCTION_DISABLED   0x89    // Function disabled via attribute(s)
#define YSM_KEY_STORAGE_LOCKED  0x8a    // Key storage locked
#define YSM_MISMATCH            0x8b    // Verification mismatch
#define YSM_INVALID_PARAMETER   0x8c    // Invalid parameter

#define YSM_CUSTOM_STATUS_FIRST 0xf0    // Start custom status codes
#define YSM_CUSTOM_STATUS_LAST  0xff    // Start custom status codes

////////////////////////////////////
//  NULL / resync command
////////////////////////////////////

#define YSM_NULL                        0x00

typedef struct {
    uint8_t allNull[YSM_MAX_PKT_SIZE - 1]; // Set all to NULL when sending resync
} YSM_RESYNC_REQ;

////////////////////////////////////
//  Generate AEAD block from data for a specific key
////////////////////////////////////

#define YSM_AEAD_GENERATE               0x01

typedef struct {
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
    uint32_t keyHandle;                 // Key handle
    uint8_t numBytes;                   // Number of data bytes
    uint8_t data[YSM_DATA_BUF_SIZE];    // Data
} YSM_AEAD_GENERATE_REQ;

#define YSM_AEAD_GENERATED              (YSM_AEAD_GENERATE | YSM_RESPONSE)

typedef struct {
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
    uint32_t keyHandle;                 // Key handle
    YSM_STATUS status;                  // Status
    uint8_t numBytes;                   // Number of bytes in AEAD block
    uint8_t aead[YSM_AEAD_MAX_SIZE];    // AEAD block
} YSM_AEAD_GENERATE_RESP;

////////////////////////////////////
//  Generate AEAD block of data buffer for a specific key
////////////////////////////////////

#define YSM_BUFFER_AEAD_GENERATE        0x02

typedef struct {
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
    uint32_t keyHandle;                 // Key handle
} YSM_BUFFER_AEAD_GENERATE_REQ;

#define YSM_BUFFER_AEAD_GENERATED       (YSM_BUFFER_AEAD_GENERATE | YSM_RESPONSE)

typedef YSM_AEAD_GENERATE_RESP YSM_BUFFER_AEAD_GENERATE_RESP;

////////////////////////////////////
//  Generate random AEAD block in one stroke
////////////////////////////////////

#define YSM_RANDOM_AEAD_GENERATE        0x03

typedef struct {
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
    uint32_t keyHandle;                 // Key handle
    uint8_t numBytes;                   // Number of bytes to randomize
} YSM_RANDOM_AEAD_GENERATE_REQ;

#define YSM_RANDOM_AEAD_GENERATED       (YSM_RANDOM_AEAD_GENERATE | YSM_RESPONSE)

typedef YSM_AEAD_GENERATE_RESP YSM_RANDOM_AEAD_GENERATE_RESP;

////////////////////////////////////
//  Decrypt AEAD block and compare with plaintext
////////////////////////////////////

#define YSM_AEAD_DECRYPT_CMP            0x04

typedef struct {
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
    uint32_t keyHandle;                 // Key handle
    uint8_t numBytes;                   // Number of data bytes (cleartext + aead)
    uint8_t data[YSM_MAX_PKT_SIZE - 0x10]; // Data (cleartext + aead). Empty cleartext validates aead only
} YSM_AEAD_DECRYPT_CMP_REQ;

#define YSM_AEAD_DECRYPT_CMPD           (YSM_AEAD_DECRYPT_CMP | YSM_RESPONSE)

typedef struct {
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
    uint32_t keyHandle;                 // Key handle
    YSM_STATUS status;                  // Status
} YSM_AEAD_DECRYPT_CMP_RESP;

////////////////////////////////////
//  Store Yubikey specific AEAD block in internal store (nonce == public id)
////////////////////////////////////

#define YSM_DB_YUBIKEY_AEAD_STORE          0x05

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id (and nonce in this case)
    uint32_t keyHandle;                  // Key handle
    uint8_t aead[YSM_YUBIKEY_AEAD_SIZE]; // AEAD block
} YSM_DB_YUBIKEY_AEAD_STORE_REQ;

#define YSM_DB_YUBIKEY_AEAD_STORED         (YSM_DB_YUBIKEY_AEAD_STORE | YSM_RESPONSE)

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id (nonce)
    uint32_t keyHandle;                 // Key handle
    YSM_STATUS status;                  // Validation status
} YSM_DB_YUBIKEY_AEAD_STORE_RESP;

////////////////////////////////////
//  Decode Yubico OTP using supplied AEAD block
////////////////////////////////////

#define YSM_AEAD_YUBIKEY_OTP_DECODE         0x06

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id (nonce)
    uint32_t keyHandle;                 // Key handle
    uint8_t otp[YSM_OTP_SIZE];          // OTP
    uint8_t aead[YSM_YUBIKEY_AEAD_SIZE]; // AEAD block
} YSM_AEAD_YUBIKEY_OTP_DECODE_REQ;

#define YSM_AEAD_YUBIKEY_OTP_DECODED    (YSM_AEAD_YUBIKEY_OTP_DECODE | YSM_RESPONSE)

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id (nonce)
    uint32_t keyHandle;                 // Key handle
    uint16_t useCtr;                    // Use counter
    uint8_t sessionCtr;                 // Session counter
    uint8_t tstph;				        // Timestamp (high part)
    uint16_t tstpl;				        // Timestamp (low part)
    YSM_STATUS status;                  // Validation status
} YSM_AEAD_YUBIKEY_OTP_DECODE_RESP;

////////////////////////////////////
// Validate OTP using interal store
////////////////////////////////////

#define YSM_DB_YUBIKEY_OTP_VALIDATE     0x07

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id
    uint8_t otp[YSM_OTP_SIZE];          // OTP
} YSM_DB_YUBIKEY_OTP_VALIDATE_REQ;

#define YSM_DB_YUBIKEY_OTP_VALIDATED    (YSM_DB_YUBIKEY_OTP_VALIDATE | YSM_RESPONSE)

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE];  // Public id
    uint16_t useCtr;                    // Use counter
    uint8_t sessionCtr;                 // Session counter
    uint8_t tstph;				        // Timestamp (high part)
    uint16_t tstpl;				        // Timestamp (low part)
    YSM_STATUS status;                  // Validation status
} YSM_DB_YUBIKEY_OTP_VALIDATE_RESP;

////////////////////////////////////
//  Store Yubikey specific AEAD block in internal store (nonce != public id)
////////////////////////////////////

#define YSM_DB_YUBIKEY_AEAD_STORE2         0x08

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id
    uint32_t keyHandle;                  // Key handle
    uint8_t aead[YSM_YUBIKEY_AEAD_SIZE]; // AEAD block
    uint8_t nonce[YSM_AEAD_NONCE_SIZE];  // Nonce
} YSM_DB_YUBIKEY_AEAD_STORE2_REQ;

#define YSM_DB_YUBIKEY_AEAD_STORED2         (YSM_DB_YUBIKEY_AEAD_STORE2 | YSM_RESPONSE)

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id
    uint32_t keyHandle;                 // Key handle
    YSM_STATUS status;                  // Validation status
} YSM_DB_YUBIKEY_AEAD_STORE2_RESP;

////////////////////////////////////
// AES ECB block encrypt request
////////////////////////////////////

#define YSM_AES_ECB_BLOCK_ENCRYPT       0x0d

typedef struct {
    uint32_t keyHandle;                 // Key handle
    uint8_t plaintext[YSM_BLOCK_SIZE];  // Plaintext block
} YSM_AES_ECB_BLOCK_ENCRYPT_REQ;

#define YSM_AES_ECB_BLOCK_ENCRYPTED (YSM_AES_ECB_BLOCK_ENCRYPT | YSM_RESPONSE)

typedef struct {
    uint32_t keyHandle;                 // Key handle
    uint8_t ciphertext[YSM_BLOCK_SIZE]; // Ciphertext block
    YSM_STATUS status;                  // Encryption status
} YSM_AES_ECB_BLOCK_ENCRYPT_RESP;

////////////////////////////////////
// ECB block decrypt request
////////////////////////////////////

#define YSM_AES_ECB_BLOCK_DECRYPT       0x0e

typedef struct {
    uint32_t keyHandle;                 // Key handle
    uint8_t ciphertext[YSM_BLOCK_SIZE]; // Ciphertext block
} YSM_AES_ECB_BLOCK_DECRYPT_REQ;

#define YSM_AES_ECB_BLOCK_DECRYPTED (YSM_AES_ECB_BLOCK_DECRYPT | YSM_RESPONSE)

typedef struct {
    uint32_t keyHandle;                 // Key handle
    uint8_t plaintext[YSM_BLOCK_SIZE];  // Plaintext block
    YSM_STATUS status;                  // Decryption status
} YSM_AES_ECB_BLOCK_DECRYPT_RESP;

////////////////////////////////////
// ECB block decrypt and verify request
////////////////////////////////////

#define YSM_AES_ECB_BLOCK_DECRYPT_CMP   0x0f

typedef struct {
    uint32_t keyHandle;                 // Key handle
    uint8_t ciphertext[YSM_BLOCK_SIZE]; // Ciphertext block
    uint8_t plaintext[YSM_BLOCK_SIZE];  // Plaintext block
} YSM_AES_ECB_BLOCK_DECRYPT_CMP_REQ;

#define YSM_AES_ECB_BLOCK_DECRYPT_CMPD (YSM_AES_ECB_BLOCK_DECRYPT_CMP | YSM_RESPONSE)

typedef struct {
    uint32_t keyHandle;                 // Key handle
    YSM_STATUS status;                  // Decryption + verification status
} YSM_AES_ECB_BLOCK_DECRYPT_CMP_RESP;

////////////////////////////////////
// HMAC-SHA1 data input
////////////////////////////////////

#define YSM_HMAC_SHA1_GENERATE          0x10

#define YSM_HMAC_SHA1_RESET     0x01    // Flag to indicate reset at first packet
#define YSM_HMAC_SHA1_FINAL     0x02    // Flag to indicate that the hash shall be calculated
#define YSM_HMAC_SHA1_TO_BUFFER 0x04    // Flag to transfer HMAC to buffer

typedef struct {
    uint32_t keyHandle;                 // Key handle
    uint8_t flags;                      // Flags
    uint8_t numBytes;                   // Number of bytes in data packet
    uint8_t data[YSM_MAX_PKT_SIZE - 6]; // Data to be written
} YSM_HMAC_SHA1_GENERATE_REQ;

#define YSM_HMAC_SHA1_GENERATED         (YSM_HMAC_SHA1_GENERATE | YSM_RESPONSE)

typedef struct {
    uint32_t keyHandle;                 // Key handle
    YSM_STATUS status;                  // Status
    uint8_t numBytes;                   // Number of bytes in hash output
    uint8_t hash[YSM_SHA1_HASH_SIZE];   // Hash output (if applicable)
} YSM_HMAC_SHA1_GENERATE_RESP;

////////////////////////////////////
// Load temporary key from AEAD input
////////////////////////////////////

#define YSM_TEMP_KEY_LOAD               0x11

typedef struct {
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce
    uint32_t keyHandle;                 // Key handle to unlock AEAD
    uint8_t numBytes;                   // Number of bytes (explicit key size 16, 20, 24 or 32 bytes + flags + MAC)
    uint8_t aead[YSM_MAX_KEY_SIZE + sizeof(uint32_t) + YSM_AEAD_MAC_SIZE]; // AEAD block (including flags)
} YSM_TEMP_KEY_LOAD_REQ;

#define YSM_TEMP_KEY_LOADED             (YSM_TEMP_KEY_LOAD | YSM_RESPONSE)

typedef struct {
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce
    uint32_t keyHandle;                 // Key handle
    YSM_STATUS status;                  // Status
} YSM_TEMP_KEY_LOAD_RESP;

////////////////////////////////////
//  Load data buffer with data
////////////////////////////////////

#define YSM_BUFFER_LOAD                 0x20

typedef struct {
    uint8_t offs;                       // Offset in buffer. Zero flushes/resets buffer first
    uint8_t numBytes;                   // Number of bytes to load
    uint8_t data[YSM_DATA_BUF_SIZE];    // Data to load
} YSM_BUFFER_LOAD_REQ;

#define YSM_BUFFER_LOADED               (YSM_BUFFER_LOAD | YSM_RESPONSE)

typedef struct {
    uint8_t numBytes;                   // Number of bytes in buffer now
} YSM_BUFFER_LOAD_RESP;

////////////////////////////////////
//  Load data buffer with random data
////////////////////////////////////

#define YSM_BUFFER_RANDOM_LOAD          0x21

typedef struct {
    uint8_t offs;                       // Offset in buffer. Zero flushes/resets buffer first
    uint8_t numBytes;                   // Number of bytes to randomize
} YSM_BUFFER_RANDOM_LOAD_REQ;

#define YSM_BUFFER_RANDOM_LOADED        (YSM_BUFFER_RANDOM_LOAD | YSM_RESPONSE)

typedef struct {
    uint8_t numBytes;                   // Number of bytes in buffer now
} YSM_BUFFER_RANDOM_LOAD_RESP;

////////////////////////////////////
//  Get new unique nonce
////////////////////////////////////

#define YSM_NONCE_GET                   0x22

typedef struct {
    uint16_t postIncrement;             // Step in post increment
} YSM_NONCE_GET_REQ;

#define YSM_NONCE_GOT                   (YSM_NONCE_GET | YSM_RESPONSE)

typedef struct {
    YSM_STATUS status;                  // Status
    uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce
} YSM_NONCE_GET_RESP;

////////////////////////////////////
// Echo (loopback test)
////////////////////////////////////

#define YSM_ECHO                        0x23

typedef struct {
    uint8_t numBytes;                   // Number of bytes in data field
    uint8_t data[YSM_MAX_PKT_SIZE - 1]; // Data
} YSM_ECHO_REQ;

#define YSM_ECHOED                      (YSM_ECHO | YSM_RESPONSE)

typedef struct {
    uint8_t numBytes;                   // Number of bytes in data field
    uint8_t data[YSM_MAX_PKT_SIZE - 1]; // Data
} YSM_ECHO_RESP;

////////////////////////////////////
// Generate random number block(s)
////////////////////////////////////

#define YSM_RANDOM_GENERATE             0x24

typedef struct {
    uint8_t numBytes;                   // Number of bytes to generate
} YSM_RANDOM_GENERATE_REQ;

#define YSM_RANDOM_GENERATED            (YSM_RANDOM_GENERATE | YSM_RESPONSE)

typedef struct {
    uint8_t numBytes;                   // Number of bytes generated
    uint8_t rnd[YSM_MAX_PKT_SIZE - 1];  // Random data
} YSM_RANDOM_GENERATE_RESP;

////////////////////////////////////
// Re-seed CTR-DRBG
////////////////////////////////////

#define YSM_RANDOM_RESEED               0x25

typedef struct {
    uint8_t seed[YSM_CTR_DRBG_SEED_SIZE]; // New seed
} YSM_RANDOM_RESEED_REQ;

#define YSM_RANDOM_RESEEDED             (YSM_RANDOM_RESEED | YSM_RESPONSE)

typedef struct {
    YSM_STATUS status;                  // Status
} YSM_RANDOM_RESEED_RESP;

////////////////////////////////////
// System information query
////////////////////////////////////

#define YSM_SYSTEM_INFO_QUERY           0x26

#define YSM_SYSTEM_INFO                 (YSM_SYSTEM_INFO_QUERY | YSM_RESPONSE)

#define YSM_SYSTEM_UID_SIZE             12      // Sizeof unique identifier

typedef struct {
    uint8_t versionMajor;               // Major version #
    uint8_t versionMinor;               // Minor version #
    uint8_t versionBuild;               // Build version #
    uint8_t protocolVersion;            // Protocol version #
    uint8_t systemUid[YSM_SYSTEM_UID_SIZE]; // System unique identifier
} YSM_SYSTEM_INFO_RESP;

////////////////////////////////////
// Unlock key handle based operations (version 0.x)
////////////////////////////////////

#define YSM_KEY_STORAGE_UNLOCK          0x27

typedef struct {
    uint8_t password[YSM_BLOCK_SIZE];  // Unlock password
} YSM_KEY_STORAGE_UNLOCK_REQ;

#define YSM_KEY_STORAGE_UNLOCKED (YSM_KEY_STORAGE_UNLOCK | YSM_RESPONSE)

typedef struct {
    YSM_STATUS status;                  // Unlock status
} YSM_KEY_STORAGE_UNLOCK_RESP;

////////////////////////////////////
// Unlock HSM mode of operation (version 1.x)
////////////////////////////////////

#define YSM_HSM_UNLOCK                  0x28

typedef struct {
    uint8_t publicId[YSM_PUBLIC_ID_SIZE]; // Public id
    uint8_t otp[YSM_OTP_SIZE];          // OTP
} YSM_HSM_UNLOCK_REQ;

#define YSM_HSM_UNLOCKED    (YSM_HSM_UNLOCK | YSM_RESPONSE)

typedef struct {
    YSM_STATUS status;                  // Unlock status
} YSM_HSM_UNLOCK_RESP;

////////////////////////////////////
// Decrypt key store
////////////////////////////////////

#define YSM_KEY_STORE_DECRYPT           0x29

typedef struct {
    uint8_t key[YSM_MAX_KEY_SIZE];      // Key store decryption key
} YSM_KEY_STORE_DECRYPT_REQ;

#define YSM_KEY_STORE_DECRYPTED     (YSM_KEY_STORE_DECRYPT | YSM_RESPONSE)

typedef struct {
    YSM_STATUS status;                  // Unlock status
} YSM_KEY_STORE_DECRYPT_RESP;

////////////////////////////////////
// Exit HSM mode (debug mode only)
////////////////////////////////////

#define YSM_MONITOR_EXIT                0x7f    // Exit to monitor (no response sent)

#define YSM_MONITOR_EXIT_MAGIC          0xbaadbeef

typedef struct {
    uint32_t magic;                     // Magic number for trigger
    uint32_t magicInv;                  // 1st complement of magic
} YSM_MONITOR_EXIT_REQ;

#define YSM_EXTENDED_CMD_FIRST          0x60
#define YSM_EXTENDED_CMD_LAST           0x6f

#endif  // __YUBIHSM_H_INCLUDED
