#ifndef _IO_ECR_HMAC_H_
#define _IO_ECR_HMAC_H_

#include <stdint.h>

#include "log.h"

#define HMAC_PAD_LENGTH 64
#define HMAC_OUT_LENGTH 20

int hmac_sha1(const uint8_t *input, uint32_t input_length, const uint8_t *key, uint32_t key_length, uint8_t output[HMAC_OUT_LENGTH]);

#endif