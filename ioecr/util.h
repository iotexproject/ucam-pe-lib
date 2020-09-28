#ifndef _IO_ECR_UTIL_H_
#define _IO_ECR_UTIL_H_

#include <stdint.h>
#include <time.h>

/*
 *  Returns:
 *  0: src and dst are the same
 *  1: src and dst are not the same
 */
int util_buffer_compare(const uint8_t *src, const uint8_t *dst, int length);

#endif /* _IO_ECR_UTIL_H_ */

