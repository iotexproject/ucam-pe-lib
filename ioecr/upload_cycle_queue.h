#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>

#include "lib.h"
#include "upload_data.h"

#ifndef _IO_ECR_UPLOAD_CYCLE_QUEUE_
#define _IO_ECR_UPLOAD_CYCLE_QUEUE_

#define CYCLE_QUEUE_STATUS_ACTIVE 0u
#define CYCLE_QUEUE_STATUS_OVERFLOW 1u

typedef struct {
    st_upload_data **buffer;
    uint32_t capacity;
    int32_t last_iframe_idx;
    int32_t next_to_last_iframe_idx;
    uint32_t remaining_count;
    int32_t index_to_write;
    int32_t last_read_index;
    uint8_t status;
    pthread_mutex_t lock; // lock of this buffer
} st_upload_cycle_queue;

uint8_t init_upload_cycle_queue(st_upload_cycle_queue *cq, uint8_t capacity);

void release_upload_cycle_queue(st_upload_cycle_queue *cq);

#define ENQUE_SUCCESS 0u
#define ENQUE_FAILED 1u
#define ENQUE_OVERFLOW 2u
uint8_t upload_cycle_enqueue(st_upload_cycle_queue *cq, st_upload_data *frame);

#define DEQUE_SUCCESS 0u
#define DEQUE_NO_DATA 1u
#define DEQUE_SUCCESS_WITH_DROP 2u
uint8_t upload_cycle_dequeue(st_upload_cycle_queue *cq, st_upload_data **frame);

#endif
