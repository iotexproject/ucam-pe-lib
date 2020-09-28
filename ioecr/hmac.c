#include <mbedtls/sha1.h>
#include <stdlib.h>
#include <string.h>

#include "hmac.h"

// hmac_sha1 = sha1(key XOR opad, sha1(key XOR ipad, input))
// opad = 0x36 repeated 64 times
// ipad = 0x5c repeated 64 times
int hmac_sha1(const uint8_t *input, uint32_t input_length, const uint8_t *key, uint32_t key_length, uint8_t output[HMAC_OUT_LENGTH]) {
  int i;
  uint8_t outter[HMAC_PAD_LENGTH + HMAC_OUT_LENGTH];
  uint8_t * inner = (uint8_t *)malloc(HMAC_PAD_LENGTH + input_length);
  if (inner == NULL) {
    log_error("malloc() failed\n");
    return -1;
  }

  if (key_length > HMAC_PAD_LENGTH) {
    mbedtls_sha1(key, key_length, output);
    key = output;
    key_length = HMAC_OUT_LENGTH;
  }
  memset(outter, 0, HMAC_PAD_LENGTH);
  memcpy(outter, key, key_length);
  memcpy(inner, outter, HMAC_PAD_LENGTH);
  for (i = 0; i < HMAC_PAD_LENGTH; i++) {
    // key XOR opad
    outter[i] ^= 0x5c;
    // key XOR ipad
    inner[i] ^= 0x36;
  }
  // inner = key XOR ipad + input
  memcpy(inner + HMAC_PAD_LENGTH, input, input_length);
  // sha1(inner, output)
  mbedtls_sha1(inner, HMAC_PAD_LENGTH + input_length, output);
  free(inner);
  inner = NULL;
  // outter = opad + sha1(inner)
  memcpy(outter + HMAC_PAD_LENGTH, output, HMAC_OUT_LENGTH);
  // sha1(outter, output)
  mbedtls_sha1(outter, HMAC_PAD_LENGTH + HMAC_OUT_LENGTH, output);

  return 0;
}