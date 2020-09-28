#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <curl/curl.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>

#include "util.h"
#include "hmac.h"
#include "config.h"

int util_buffer_compare(const uint8_t *src, const uint8_t *dst, int length) {
  assert(src != NULL);
  assert(dst != NULL);

  int i;
  uint8_t result = src[0] ^ dst[0];
  for (i = 1; i < length; i++) {
    result |= (src[i] ^ dst[i]);
  }
  return result != 0;
}
