#ifndef _IOECR_ENCRYPTOR_H_
#define _IOECR_ENCRYPTOR_H_

#include <stdint.h>
#include <stdlib.h>

#include "key_store.h"

/**
 * @brief  Release interal resources hold by ioecr library.
 * @note
 * @retval None
 */
void release_encryptor();

/**
 * @brief  Initialize IOECR library context for privacy.
 * @note   This function initializes encryption component.
 * @retval 0 : success
 *         <0: error code returned from internal components, such as,log, context's init routines.
 */
int initialize_encryptor();

/**
 * @brief  Encrypt a data buffer
 * @note   This function encrypts the buffer data in place, i.e. the resulting cipher replaces the
 *         plain text in the origal buffer.
 *         The encrytion uses AES CTR mode, so there is no expansion in cipher, but a 16 byte
 *         nonce|counter value will be returned to a caller-provided buffer pointed by nonce_counter.
 *         The key used for encryption should be set using ioecr_set_key() beforehand. To confirme the
 *         right key is used, a proceeding 4 bytes of SHA1 of the key used is copied to caller provided
 *         buffer key_hash.
 * @param  *buffer: Point to buffer to hold data to encrypt and resulting cipher
 * @param  buffer_size: The size of data to be encrypted.
 * @param  *nonce_counter: Point to a 16-byte buffer to hold returned initial nonce|counter to encrypt the data.
 * @param  *key_hash: Point to a 4-byte buffer to hold inital 4 bytes of key sha1 hash.
 * @retval   0 : user disabled encryption, do nothing on input buffer
 *           1 : success. 1=encryption algorithm ID
 *          -1 : null pointer input
 *         <-1 : error code from mbedtls library
 */
int encrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, uint8_t *key_hash);

/**
 * @brief  Decrypt a data buffer
 * @note   This function decrypts the buffer data in place, i.e. the plain text replaces the
 *         cipher text in the origal buffer.
 * @param  *buffer: Point to buffer to hold data to decrypt
 * @param  buffer_size: The size of data to be decrypted.
 * @param  *nonce_counter: Point to a 16-byte buffer storing nonce|counter during encryption.
 * @param  *key_hash: Point to a 4-byte buffer to hold inital 4 bytes of key sha1 hash. If key
 *                    hash is null, key verification will be skipped.
 * @retval   0 : success
 *           1 : null pointer input
 *           2 : failed to get lock
 *           4 : invalid key hash
 *         <-1 : error code from mbedtls library
 */
int decrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, const uint8_t *key_hash);

/**
 * @brief  Set frame encryption key
 * @note   The function set a new frame encryption key, replacing the current key. To make sure the current
 *         key is not overwritten by mistake, the hash of the current key should be provided.
 * @param  nonce: nonce of the encryption key
 * @param  new_key: Point to a 16-byte new key to be set.
 * @param  new_key_length: Key length in byte. Must be 16.
 * @param  *curr_key_hash: Point to the hash of the current key.
 * @param  hash_length: Length of hash.
 * @retval The returned value is encoded as:
 *         bit 0: 0 -- success
 *                1 -- invalid input, null pointer, or key is not 16-byte long, or hash is not 20-byte long
 *         bit 1: 0 -- success
 *                1 -- library failed to operate mutex
 *         bit 2: 0 -- encryption disabled
 *                1 -- encryption enabled
 *         bit 3: 0 -- key hash match
 *                1 -- key hash does not match
 *         bit 4: 0 -- new key update success
 *                1 -- failed on write new key into key file
 */
int set_encryption_key(uint32_t nonce, const uint8_t* new_key, int new_key_length, const uint8_t *curr_key_hash, int hash_length);

/**
 * @brief  Check encrytion status and verify key
 * @note   This function can be used to verify if a key is used as current encryption key,
 *         and could be used to check if the encryption is turned on or off.
 * @param  hash: hash(SHA1) of the key to verify.
 * @param  length: length of the hash in byte, must be 20.
 * @retval The returned value is encoded as:
 *         bit 0: 0 -- success
 *             1 -- invalid input, null pointer, or hash is not 20-byte long
 *         bit 1: 0 -- success
 *             1 -- library failed to operate mutex
 *         bit 2: 0 -- encryption disabled
 *             1 -- encryption enabled
 *         bit 3: 0 -- key hash match
 *             1 -- key hash does not match
 */
int check_key(const uint8_t* hash, int length, uint32_t *nonce);

#endif
