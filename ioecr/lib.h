#ifndef _IO_ECR_LIB_H_
#define _IO_ECR_LIB_H_
#include <pthread.h>
#include <stdint.h>

/**
 * @brief length of AES 128 in bytes
 */
#define AES128_BLOCK_LENGTH 16

/**
 * @brief length of encryption key
 */
#define IOECR_KEY_LENGTH    16

/**
 * @brief length of the encryption key hash
 * @note first 4-byte of encryption key's HMAC used as checksum to compare against current key
 */
#define IOECR_HASH_LENGTH   4

/**
 * @brief Error mask for returned value from ioecr_set_encryption_key() and
 *  ioecr_check_encryption_key(), bit 0: invalid input
 */
#define IOECR_KEY_E_LEN     1

/**
 * @brief Error mask for returned value from ioecr_set_encryption_key() and
 *  ioecr_check_encryption_key(), bit 1: failed to obtain lock
 */
#define IOECR_KEY_E_LOCK    2

/**
 * @brief Error mask for returned value from ioecr_set_encryption_key() and
 *  ioecr_check_encryption_key(), bit 2: encryption is enabled
 */
#define IOECR_KEY_ENABLED   4

/**
 * @brief Error mask for returned value from ioecr_set_encryption_key() and
 *  ioecr_check_encryption_key(), bit 3: key hash does not match
 */
#define IOECR_KEY_E_VERIFY  8

/**
 * @brief Error mask for returned value from ioecr_set_encryption_key() and
 *  ioecr_check_encryption_key(), bit 4: failed to write key file
 */
#define IOECR_KEY_E_WRITE   16

/**
 * @brief type of upload data
 */
typedef enum {
    SNAPSHOT = 0,
    SNAPSHOT_INDEX,
    VIDEO,
    VIDEO_INDEX
} UPLOAD_DATA_TYPE;

/**
 * @brief  Structure of frame information, to be passed to ioecr_receive_frame
 */
typedef struct {
  /**
   * @brief pointer of frame buffer
   */
  uint8_t *buffer;
  /**
   * @brief total size of frame in bytes
   */
  uint32_t size;
  /**
   * @brief channel number
   */
  uint32_t channel;
  /**
   * @brief video codec id
   */
  uint32_t codecid;
  /**
   * @brief type of frame
   */
  uint32_t frametype;
  /**
   * @brief start time of the frame
   */
  uint32_t pts;
  /**
   * @brief bash of encryption key (first 4 bytes)
   */
  uint8_t  hash[IOECR_HASH_LENGTH];
  /**
   * @brief encription sdk version
   */
  uint8_t  version;
  /**
   * @brief ID of encryption algorithm
   * @note 0 stands for not encrypted
   */
  uint8_t  encryptID;
} st_frame_info;

/**
 * @brief  Structure of frame header to attached to a frame
 */
typedef struct {
  /**
   * @brief total length of the encrypted frame in bytes, including header
   */
  uint32_t size;
  /**
   * @brief size of header in bytes
   */
  uint32_t headersize;
  /**
   * @brief channel number
   */
  uint32_t channel;
  /**
   * @brief video codec id
   */
  uint32_t codecid;
  /**
   * @brief type of frame
   */
  uint32_t frametype;
  /**
   * @brief start time of the frame
   */
  uint32_t pts;
  /**
   * @brief bash of encryption key (first 4 bytes)
   */
  uint8_t  hash[IOECR_HASH_LENGTH];
  /**
   * @brief encription sdk version
   */
  uint8_t  version;
  /**
   * @brief ID of encryption algorithm
   * @note 0 stands for not encrypted
   */
  uint8_t  encryptID;
  /**
   * @brief pad to 4-byte aligned
   */
  uint8_t  reserved[2];
} st_frame_header;

/**
 * @brief  Structure of credential data
 */
typedef struct {
  /**
   * @brief uid of the device
   */
  char *uid;
  /**
   * @brief length of the uid
   */
  uint32_t uid_length;
  /**
   * @brief password of the device
   */
  char *password;
  /**
   * @brief length of the password
   */
  uint32_t password_length;
} st_credential;

/**
 * @brief  Type of the callback registered by camera firmware to get uploader.
 */
typedef int (*cb_get_uploader)(void **uploader, st_credential *credential);

/**
 * @brief  Type of the callback registered by camera firmware to release uploader.
 */
typedef void (*cb_release_uploader)(void **uploader);

/**
 * @brief  Type of the callback registered by camera firmware to process frame with uploader.
 */
typedef void (*cb_process_frame)(void *uploader, void *frame);

/**
 * @brief  Type of the callback registered by camera firmware to get credential.
 */
typedef int (*cb_get_credential)(st_credential *c);

/**
 * @brief  Type of the callback registered by camera firmware to release credential.
 */
typedef int (*cb_release_credential)(st_credential *c);

/**
 * @brief Type of the callback processing ota write data
 */
typedef size_t (*cb_write_ota_data)(void *ptr, size_t size, size_t nmemb, void *stream);

/**
 * @brief Type of the callback updating ota progress
 */
typedef void (*cb_update_ota_progress)(uint8_t percentage);

/**
 * @brief  Get libioecr version string into caller-provided buffer.
 * @note
 * @param  buf: point to buffer to hold returned version string
 * @param  size: size of provided buffer
 * @retval action result
 *
 *         0: success
 *         1: fail, buf size is too small to hold the returned string
 */
int ioecr_get_version(uint8_t* buf, uint32_t size);

/**
 * @brief  Check encrytion status and verify key
 * @note   This function can be used to verify if a key is used as current encryption key,
 *         and could be used to check if the encryption is turned on or off.
 * @param  hash: hash(SHA1) of the key to verify.
 * @param  length: length of the hash in byte, must be 20.
 * @param  nonce: nonce of the current encryption key.
 * @retval encoded value:
 *
 *         bit 0: 0 -- success
 *                1 -- invalid input, null pointer, or hash is not 20-byte long
 *         bit 1: 0 -- success
 *                1 -- library failed to operate mutex
 *         bit 2: 0 -- encryption disabled
 *                1 -- encryption enabled
 *         bit 3: 0 -- key hash match
 *                1 -- key hash does not match
 */
int ioecr_check_encryption_key(const uint8_t* hash, int length, uint32_t *nonce);

/**
 * @brief  Initialize encryptor component
 * @note   This function initializes encryption component.
 * @retval action result
 *
 *         0 : success
 *         others: error code returned from internal components, such as,log, context's init routines.
 */
int ioecr_initialize_encryptor();

/**
 * @brief Release internal resources hold by encryptor
 */
void ioecr_release_encryptor();

/**
 * @brief  Encrypt a data buffer
 * @note   This function encrypts the buffer data in place, i.e. the resulting cipher replaces the
 *         plain text in the origal buffer.
 *         The encrytion uses AES CTR mode, so there is no expansion in cipher, but a 16 byte
 *         nonce|counter value will be returned to a caller-provided buffer pointed by nonce_counter.
 *         The key used for encryption should be set using ioecr_set_key() beforehand. To confirme the
 *         right key is used, a proceeding 4 bytes of SHA1 of the key used is copied to caller provided
 *         buffer key_hash.
 * @param  buffer: Point to buffer to hold data to encrypt and resulting cipher
 * @param  buffer_size: The size of data to be encrypted.
 * @param  nonce_counter: Point to a 16-byte buffer to hold returned initial nonce|counter to encrypt the data.
 * @param  key_hash: Point to a 4-byte buffer to hold inital 4 bytes of key sha1 hash.
 * @retval action result
 *
 *         >= 0 : id of encryption algorithm, success
 *         -1 : invalid input
 *         <-1 : error code from mbedtls library
 */
int ioecr_encrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, uint8_t *key_hash);

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
int ioecr_decrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, const uint8_t *key_hash);

/**
 * @brief Start a thread to download new firmware
 *
 * @param url new version firmware url
 * @param save_to local path to save new firmware
 * @param write_data callback function to write ota data
 * @param update_progress callback function to update ota download progress
 * @param pthreadid thread id
 * @return int
 *          0: success
 *          1: failed
 */
int ioecr_ota(const char *url, const char *save_to, cb_write_ota_data write_data, cb_update_ota_progress update_progress, pthread_t *pthreadid);

/**
 * @brief  Set frame encryption key
 * @note   The function set a new frame encryption key, replacing the current key. To make sure the current
 *         key is not overwritten by mistake, the hash of the current key should be provided.
 * @param  nonce: Nonce of the encryption
 * @param  new_key: Point to a 16-byte new key to be set.
 * @param  new_key_length: Key length in byte. Must be 16.
 * @param  *curr_key_hash: Point to the hash of the current key.
 * @param  hash_length: Length of hash.
 * @retval encoded value of result:
 *
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
int ioecr_set_encryption_key(uint32_t nonce, const uint8_t* new_key, int new_key_length, const uint8_t *curr_key_hash, int hash_length);

/**
 * @brief  Initialize IOECR library context for recording.
 * @note   This function registers callbacks, and initializes internal components.
 * @param  get_frame: get frame function call back.
 * @param  release_frame: release frame function call back.
 * @param  get_credential: callback function to return a credential
 * @param  release_credential: callback function to release a credential
 * @retval action result
 *
 *         0: success
 *         1: fail
 */
int ioecr_initialize_recorder(
    cb_get_credential get_credential,
    cb_release_credential release_credential);

/**
 * @brief  Release internal resources hold by recorder.
 */
void ioecr_release_recorder();

/**
 * @brief Send a frame to recorder
 * @param frame to be processed by recorder
 */
void ioecr_receive_frame(st_frame_info *frame);

/**
 * @brief Disable upload
 * @note  This function disables the recorder to upload video to cloud.
 * @retval action result
 *
 *         0: success
 *         others: fail
 */
int ioecr_disable_upload();

/**
 * @brief Enable upload
 * @note  This function enables the recorder to upload video to cloud.
 * @retval action result
 *
 *         0: success
 *         others: fail
 */
int ioecr_enable_upload();

/**
 * @brief  Check whether upload has been disabled
 * @note   This function check whether video upload has been disabled.
 * @retval whether upload is disabled
 *
 *         0: enabled
 *         1: disabled
 */
uint8_t ioecr_upload_disabled();

/**
 * @brief  Start recording
 * @note   This is non-blocking call, which creates a joinable main thread and return
 *         the thread ID.
 *         The main thread will further create other threads to get token and
 *         upload address, and eventually upload video and snapshot frames
 *         to the cloud. After those thread are done, the main thread join them. The caller
 *         of this function is responsible to join the main thread with the thread ID
 *         returned in pthreadid.
 * @param  pthreadid: return the created thread ID.
 * @retval result of function call
 *
 *         0: success
 *         1: for callbacks are not registerd
 *         2: thread creation fails
 */
int ioecr_start_recording(pthread_t* pthreadid);

#endif
