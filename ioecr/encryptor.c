#include <string.h>

#include "config.h"
#include "encryptor.h"
#include "log.h"

#ifndef _UCAM_LOG_ENCRYPTOR_FILE_
#define _UCAM_LOG_ENCRYPTOR_FILE_ "/rom/ucam-encryptor.log"
#endif

static st_keystore g_keystore;

int check_key(const uint8_t* hash, int length, uint32_t *nonce) {
  int ret;
  st_keystore *ks = &(g_keystore);

  if ((ret = ks_lock(ks)) != 0) {
    return IOECR_KEY_E_LOCK;
  }

  ret = ks_check_key(ks, hash, length);
  *nonce = ks->nonce;
  ks_unlock(ks);
  return ret;
}

int set_encryption_key(uint32_t nonce, const uint8_t *enc_key, int length, const uint8_t *curr_key_hash, int hash_length) {
  int ret;
  st_keystore *ks = &(g_keystore);

  if (enc_key != NULL && length != IOECR_KEY_LENGTH) {
    log_error("Key must be %d bytes\n", IOECR_KEY_LENGTH);
    return IOECR_KEY_E_LEN;
  }

  if ((ret = ks_lock(ks)) != 0) {
    return IOECR_KEY_E_LOCK;
  }
  // handle key hash mismatch only when encryption is enabled
  ret = ks_check_key(ks, curr_key_hash, hash_length);
  if (ret == IOECR_KEY_E_LEN || ret == (IOECR_KEY_ENABLED | IOECR_KEY_E_VERIFY)) {
    ks_unlock(ks);
    return ret;
  }
  // store the new key (in ciphertext) to file
  if (ks_write_encrypt_key(nonce, enc_key, IOECR_KEY_LENGTH) != 0) {
    ks_unlock(ks);
    return (ret | IOECR_KEY_E_WRITE);
  }
  ks_set_key(ks, enc_key, nonce);
  log_info("Key file generated, written to %s\n", ENCRY_KEY_FILE);
  // new key update success, key hash must match
  // so only check encryption enable/disable before return
  ret = 0;
  if (ks_encryption_enabled(ks)) {
    ret = IOECR_KEY_ENABLED;
  }
  ks_unlock(ks);
  return ret;
}

int encrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, uint8_t *key_hash) {
  int ret;
  st_keystore *ks = &(g_keystore);

  if (buffer == NULL || nonce_counter == NULL || key_hash == NULL) {
    return -1;
  }
  if ((ret = ks_lock(ks)) != 0) {
    return -1;
  }
  ret = ks_encrypt(ks, buffer, buffer_size, nonce_counter, key_hash);
  ks_unlock(ks);

  return ret;
}

int decrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, const uint8_t *key_hash) {
  int ret;
  st_keystore *ks = &(g_keystore);
  if (buffer == NULL) {
    return 1;
  }
  if ((ret = ks_lock(ks)) != 0) {
    return 2;
  }
  ret = ks_decrypt(ks, buffer, buffer_size, nonce_counter, key_hash);
  ks_unlock(ks);

  return ret;
}

int initialize_encryptor() {
    int ret;
    if ((ret = ks_init(&(g_keystore))) != 0) {
        log_error("failed to init encryption component\n");
        return ret;
    }
/*
    if ((ret = log_init(_UCAM_LOG_ENCRYPTOR_FILE_)) != 0) {
        log_error("failed to init log");
        return ret;
    }
*/
    log_warn("initialize encryptor");
    return 0;
}

void release_encryptor() {
    ks_release(&(g_keystore));
    log_close_fp();
}
