#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "hmac.h"
#include "key_store.h"
#include "util.h"

static const char *personalization = "frame_encrypt_specific_string";
// OTP is a temporary way to store key in device in non-plaintext. It will be stored in some trusted zone in V2.0
static const uint8_t OTP[IOECR_KEY_LENGTH] = {};
static const uint8_t ZERO[IOECR_KEY_LENGTH] = {};

/*
 *  Returns: 
 *  0: success
 * -1: read file error
 *  1: file not exist
 */
int ks_read_encrypt_key(uint8_t *enc_key, uint32_t *nonce) {
  int size;
  FILE *fp;
  if ((fp = fopen(ENCRY_KEY_FILE, "re")) == NULL) {
    // key file not exist yet, encryption disable
    memcpy(enc_key, OTP, IOECR_KEY_LENGTH);
    return 1;
  }
  if ((size = fread(nonce, sizeof(uint32_t), 1, fp)) != 1) {
    log_error("read %d bytes less than expected %d\n", size, IOECR_KEY_LENGTH);
    return -1;
  }
  log_info("read nonce from key: %d\n", *nonce);
  // read file and verify size
  if ((size = fread(enc_key, 1, IOECR_KEY_LENGTH, fp)) != IOECR_KEY_LENGTH) {
    log_error("read %d bytes less than expected %d\n", size, IOECR_KEY_LENGTH);
    return -1;
  }
  fclose(fp);
  fp = NULL;
  return 0;
}

/*
 *  Returns: 
 *  0: success
 * -1: write file error
 */
int ks_write_encrypt_key(uint32_t nonce, const uint8_t *enc_key, int length) {
  int size;
  FILE *fp;
  if (enc_key == NULL) {
    enc_key = OTP;
  } else if (length != IOECR_KEY_LENGTH) {
    log_error("null input or invalid length %d\n", length);
    return -1;
  }
  if ((fp = fopen(ENCRY_KEY_FILE, "we")) == NULL) {
    log_error("Key file %s open error!\n", ENCRY_KEY_FILE);
    return -1;
  }
  if ((size = fwrite(&nonce, sizeof(uint32_t), 1, fp)) != 1) {
    log_error("failed to write nonce");
    return -1;
  }
  if ((size = fwrite(enc_key, 1, IOECR_KEY_LENGTH, fp)) != IOECR_KEY_LENGTH) {
    log_error("write %d bytes less than expected %d\n", size, IOECR_KEY_LENGTH);
    return -1;
  }
  fclose(fp);
  fp = NULL;
  return 0;
}

/*
 *  Returns: 
 *  0: success
 *  IOECR_KEY_E_LOCK: failed to obtain mutex
 */
int ks_lock(st_keystore *ks) {
  if (pthread_mutex_lock(&ks->lock) != 0) {
    return IOECR_KEY_E_LOCK;
  }
  return 0;
}

void ks_unlock(st_keystore *ks) {
  pthread_mutex_unlock(&ks->lock);
}

/*
 *  Returns: 
 *  0: encryption is disabled
 *  1: encryption is enabled
 */
int ks_encryption_enabled(st_keystore *ks) {
  return util_buffer_compare(ZERO, ks->encrypt_key, IOECR_KEY_LENGTH) != 0;
}

/*
 *  Returns: 
 *  0: success
 * <0: specific error from mbedtls lib
 */
int ks_encrypt(st_keystore *ks, uint8_t *input, uint32_t length, uint8_t *nonce_counter, uint8_t *keyhash) {
  int ret;
  size_t nc_off = 0;
  uint8_t nc[AES128_BLOCK_LENGTH], stream_block[AES128_BLOCK_LENGTH] = {0};
  if (ks_encryption_enabled(ks) == 0) {
    memcpy(keyhash, ks->key_hash, IOECR_HASH_LENGTH);
    return 0;
  }

  // set random nonce
  memset(nonce_counter, 0, AES128_BLOCK_LENGTH);
  if ((ret = mbedtls_ctr_drbg_random(&ks->ctr_drbg, nonce_counter, 12)) != 0) {
    log_error("mbedtls_ctr_drbg_random error = %d\n", ret);
    return ret;
  }
  nc_off = 0;
  memcpy(nc, nonce_counter, AES128_BLOCK_LENGTH);
  if ((ret = mbedtls_aes_crypt_ctr(&ks->aes_ctx, length, &nc_off, nc, stream_block, input, input)) != 0) {
    log_error("mbedtls_aes_crypt_ctr error = %d\n", ret);
    return ret;
  }
  // copy 4-byte keyhash
  memcpy(keyhash, ks->key_hash, IOECR_HASH_LENGTH);
  return AES128_CTR;
}

int ks_decrypt(st_keystore *ks, uint8_t *input, uint32_t length, uint8_t *nonce_counter, const uint8_t *keyhash) {
  int ret;
  size_t nc_off = 0;
  uint8_t stream_block[AES128_BLOCK_LENGTH] = {0};
  if (ks_encryption_enabled(ks) == 0) {
    if (nonce_counter != NULL) {
      return 1;
    }
    if (keyhash != NULL && strcmp((const char *)ks->key_hash, (const char *)keyhash) != 0) {
      return 4;
    }
    return 0;
  }
  if (keyhash != NULL && strcmp((const char *)ks->key_hash, (const char *)keyhash) != 0) {
    return 4;
  }
  if ((ret = mbedtls_aes_crypt_ctr(&ks->aes_ctx, length, &nc_off, nonce_counter, stream_block, input, input)) != 0) {
    return ret;
  }
  return 0;
}

int ks_check_key(st_keystore *ks, const uint8_t *hash, int length) {
  int ret = 0;
  if (hash == NULL || length != HMAC_OUT_LENGTH) {
    return IOECR_KEY_E_LEN;
  }

  if (ks_encryption_enabled(ks) != 0) {
    ret = IOECR_KEY_ENABLED;
  }

  if (util_buffer_compare(ks->key_hash, hash, length) != 0) {
    ret |= IOECR_KEY_E_VERIFY;
  }

  return ret;
}

/*
 *  input is encrypted key 
 *  it performs key decryption and computes key hash 
 *  an all-0 input indicates to disable encryption
 */
void ks_set_key(st_keystore *ks, const uint8_t *enc_key, uint32_t nonce) {
  int i;
  // decrypt the key
  if (enc_key == NULL) {
    for (i = 0; i < IOECR_KEY_LENGTH; i++) {
      ks->encrypt_key[i] = 0;
    }
  } else {
    for (i = 0; i < IOECR_KEY_LENGTH; i++) {
      ks->encrypt_key[i] = enc_key[i] ^ OTP[i];
    }
  }
  mbedtls_aes_setkey_enc(&(ks->aes_ctx), ks->encrypt_key, 128);
  // compute the HMAC of current encryption key
  hmac_sha1(ks->encrypt_key, IOECR_KEY_LENGTH, OTP, IOECR_KEY_LENGTH, ks->key_hash);
  log_info("nonce set to %d\n", nonce);
  ks->nonce = nonce;
}

int ks_init(st_keystore *ks) {
  int ret;
  uint8_t enc_key[IOECR_KEY_LENGTH];
  uint32_t nonce = 0;
  // initialize AES context
  mbedtls_aes_init(&ks->aes_ctx);
  mbedtls_entropy_init(&ks->entropy);
  mbedtls_ctr_drbg_init(&ks->ctr_drbg);
  if ((ret = mbedtls_ctr_drbg_seed(&ks->ctr_drbg,
    mbedtls_entropy_func,
    &ks->entropy,
    (const unsigned char *)personalization,
    strlen(personalization))) != 0) {
    return ret;
  }
  // load encryption key
  ret = ks_read_encrypt_key(enc_key, &nonce);
  if (ret < 0) {
    return ret;
  }
  if (ret == 0) {
    ks_set_key(ks, enc_key, nonce);
  } else {
    ks_set_key(ks, NULL, 0);
  }
  return pthread_mutex_init(&ks->lock, NULL);
}

void ks_release(st_keystore *ks) {
  pthread_mutex_destroy(&ks->lock);
  mbedtls_ctr_drbg_free(&ks->ctr_drbg);
  mbedtls_entropy_free(&ks->entropy);
  mbedtls_aes_free(&ks->aes_ctx);
}
