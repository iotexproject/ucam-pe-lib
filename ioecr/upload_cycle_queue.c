#include <stdio.h>
#include <string.h>

#include "upload_cycle_queue.h"

#ifndef _MAX_CYCLE_QUEUE_BUFFER_
#define _MAX_CYCLE_QUEUE_BUFFER_ 10
#endif

void release_upload_cycle_queue(st_upload_cycle_queue *cq) {
    int i = 0;
    pthread_mutex_lock(&cq->lock);
    if (cq->capacity != 0 && cq->buffer != NULL) {
        for (i = 0; i < _MAX_CYCLE_QUEUE_BUFFER_; i++) {
            free_upload_data(cq->buffer[i]);
            cq->buffer[i] = NULL;
        }
        free(cq->buffer);
    }
    cq->capacity = 0;
    cq->buffer = NULL;
    cq->remaining_count = 0;
    pthread_mutex_unlock(&cq->lock);
    pthread_mutex_destroy(&(cq->lock));
}

uint8_t init_upload_cycle_queue(st_upload_cycle_queue *cq, uint8_t capacity) {
    int i;
    if (cq == NULL) {
        return 1;
    }
    if (cq->capacity != 0) {
        return 2;
    }
    if (capacity > _MAX_CYCLE_QUEUE_BUFFER_) {
        return 3;
    }
    if (capacity == 0) {
        capacity = _MAX_CYCLE_QUEUE_BUFFER_;
    }
    cq->capacity = capacity;
    cq->remaining_count = 0;
    cq->status = CYCLE_QUEUE_STATUS_ACTIVE;
    cq->index_to_write = 0;
    cq->last_read_index = -1;
    cq->buffer = calloc(cq->capacity, sizeof(st_upload_data *));
    for (i = 0; i < cq->capacity; i++) {
        cq->buffer[i] = NULL;
    }
    return pthread_mutex_init(&(cq->lock), NULL);
}

uint8_t _enqueue(st_upload_cycle_queue *cq, st_upload_data *ud) {
    if (cq->capacity == 0) {
        free_upload_data(ud);
        return ENQUE_FAILED;
    }
    if (cq->remaining_count >= cq->capacity) {
        free_upload_data(ud);
        cq->status = CYCLE_QUEUE_STATUS_OVERFLOW;
        return ENQUE_OVERFLOW;
    }
    if (cq->buffer[cq->index_to_write] != NULL) {
        free_upload_data(cq->buffer[cq->index_to_write]);
    }
    cq->buffer[cq->index_to_write] = ud;
    cq->index_to_write = (cq->index_to_write + 1) % cq->capacity;
    // update read related variables
    cq->remaining_count++;
    return ENQUE_SUCCESS;
}

uint8_t upload_cycle_enqueue(st_upload_cycle_queue *cq, st_upload_data *ud) {
    uint8_t retval;
    pthread_mutex_lock(&(cq->lock));
    retval = _enqueue(cq, ud);
    pthread_mutex_unlock(&(cq->lock));
    return retval;
}

uint8_t _dequeue(st_upload_cycle_queue *cq, st_upload_data **ud) {
    *ud = NULL;
    if (cq->remaining_count == 0) {
        return DEQUE_NO_DATA;
    }
    cq->last_read_index = (cq->last_read_index + 1) % cq->capacity;
    *ud = cq->buffer[cq->last_read_index];
    cq->buffer[cq->last_read_index] = NULL;
    cq->remaining_count--;
    if (cq->status != CYCLE_QUEUE_STATUS_OVERFLOW) {
        return DEQUE_SUCCESS;
    }
    return DEQUE_SUCCESS_WITH_DROP;
}

uint8_t upload_cycle_dequeue(st_upload_cycle_queue *cq, st_upload_data **ud) {
    uint8_t retval;
    pthread_mutex_lock(&(cq->lock));
    retval = _dequeue(cq, ud);
    pthread_mutex_unlock(&(cq->lock));
    return retval;
}
