#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>

#include "lib.h"

#ifndef _IO_ECR_FRAME_BUFFER_
#define _IO_ECR_FRAME_BUFFER_

#define BUFFER_STATUS_STANDBY 0u
#define BUFFER_STATUS_ACTIVE 1u
#define BUFFER_STATUS_OVERFLOW 2u

typedef struct {
    st_frame_info **frames;
    uint32_t capacity;
    int32_t last_iframe_idx;
    int32_t next_to_last_iframe_idx;
    uint32_t remaining_count;
    int32_t index_to_write;
    int32_t index_to_read;
    uint8_t status;
    pthread_mutex_t lock; // lock of this buffer
} st_frame_buffer;

uint8_t init_frame_buffer(st_frame_buffer *buffer);

void release_frame_buffer(st_frame_buffer *buffer);

uint8_t activate_frame_buffer(st_frame_buffer *buffer);

uint8_t deactivate_frame_buffer(st_frame_buffer *buffer);

#define APPEND_FRAME_SUCCESS 0u
#define APPEND_FRAME_FAILED 1u
#define APPEND_FRAME_OVERFLOW 2u
uint8_t append_frame(st_frame_buffer *buffer, st_frame_info *frame);

#define POP_FRAME_SUCCESS 0u
#define POP_FRAME_FAIL_TO_COPY 1u
#define POP_FRAME_NOT_ACTIVE 2u
#define POP_FRAME_NO_DATA 3u
#define POP_FRAME_SUCCESS_BUT_OVERFLOW 4u
#define POP_FRAME_NO_DATA_AND_OVERFLOW 5u
uint8_t pop_frame(st_frame_buffer *buffer, st_frame_info **frame);

#endif
