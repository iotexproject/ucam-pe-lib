#ifndef _IO_ECR_KEYSTORE_H_
#define _IO_ECR_KEYSTORE_H_

#include <pthread.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "hmac.h"

#define AES128_CTR  1
#define AES128_BLOCK_LENGTH 16
#define IOECR_HASH_LENGTH   4     // first 4-byte of encryption key's HMAC used as checksum to compare against current key
#define IOECR_KEY_LENGTH    16    // support 16-byte long key now

/**
 *  Error mask for returned value from
 *  ioecr_set_encryption_key() and ioecr_check_encryption_key()
 */
#define IOECR_KEY_E_LEN     1     // bit0: invalid input
#define IOECR_KEY_E_LOCK    2     // bit1: failed to obtain mutex
#define IOECR_KEY_ENABLED   4     // bit2: encryption is enabled
#define IOECR_KEY_E_VERIFY  8     // bit3: key hash does not match
#define IOECR_KEY_E_WRITE   16    // bit4: failed to write key file

typedef struct {
    pthread_mutex_t lock;
    mbedtls_aes_context aes_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t encrypt_key[IOECR_KEY_LENGTH];
    uint32_t nonce;
    uint8_t key_hash[HMAC_OUT_LENGTH];
} st_keystore;

int ks_read_encrypt_key(uint8_t *enc_key, uint32_t *nonce);

int ks_write_encrypt_key(uint32_t nonce, const uint8_t *enc_key, int length);

int ks_lock(st_keystore *ks);

void ks_unlock(st_keystore *ks);

int ks_encryption_enabled(st_keystore *ks);

int ks_encrypt(st_keystore *ks, uint8_t *input, uint32_t length, uint8_t *nonce_counter, uint8_t *keyhash);

int ks_decrypt(st_keystore *ks, uint8_t *input, uint32_t length, uint8_t *nonce_counter, const uint8_t *keyhash);

int ks_check_key(st_keystore *ks, const uint8_t *hash, int length);

void ks_set_key(st_keystore *ks, const uint8_t *enc_key, uint32_t nonce);

int ks_init(st_keystore *ks);

void ks_release(st_keystore *ks);

#endif // _IO_ECR_KEYSTORE_H_
