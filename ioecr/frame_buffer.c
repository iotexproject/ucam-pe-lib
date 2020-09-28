#include <stdio.h>
#include <string.h>

#include "frame_buffer.h"

#ifndef _MAX_BACKWARD_FRAME_NUM_
#define _MAX_BACKWARD_FRAME_NUM_ 180
#endif

#ifndef _MAX_NUM_OF_FRAMES_
#define _MAX_NUM_OF_FRAMES_ 480
#endif

void _free_frame(st_frame_info *frame) {
    if (frame != NULL) {
        if (frame->buffer != NULL) {
            free(frame->buffer);
        }
        free(frame);
    }
}

void release_frame_buffer(st_frame_buffer *buffer) {
    int i = 0;
    pthread_mutex_lock(&buffer->lock);
    if (buffer->frames != NULL) {
        for (i = 0; i < buffer->capacity; i++) {
            if (buffer->frames[i] != NULL) {
                _free_frame(buffer->frames[i]);
                buffer->frames[i] = NULL;
            }
        }
        free(buffer->frames);
    }
    buffer->capacity = 0;
    buffer->remaining_count = 0;
    pthread_mutex_unlock(&buffer->lock);
    pthread_mutex_destroy(&(buffer->lock));
}

uint8_t init_frame_buffer(st_frame_buffer *buffer) {
    int i;
    buffer->capacity = _MAX_NUM_OF_FRAMES_;
    buffer->remaining_count = 0;
    buffer->status = BUFFER_STATUS_STANDBY;
    buffer->index_to_write = 0;
    buffer->index_to_read = -1;
    buffer->last_iframe_idx = -1;
    buffer->next_to_last_iframe_idx = -1;
    buffer->frames = calloc(buffer->capacity, sizeof(st_frame_info *));
    if (buffer->frames == NULL) {
        return 1;
    }
    for (i = 0; i < buffer->capacity; i++) {
        buffer->frames[i] = NULL;
    }
    return pthread_mutex_init(&(buffer->lock), NULL);
}

uint8_t _activate_frame_buffer(st_frame_buffer *buffer) {
    if (buffer->status != BUFFER_STATUS_STANDBY) {
        return 1;
    }
    buffer->status = BUFFER_STATUS_ACTIVE;
    if (buffer->next_to_last_iframe_idx >= 0) {
        buffer->index_to_read = buffer->next_to_last_iframe_idx;
        buffer->remaining_count = (buffer->index_to_write + buffer->capacity - buffer->index_to_read) % buffer->capacity;
        if (buffer->remaining_count <= _MAX_BACKWARD_FRAME_NUM_) {
            return 0;
        }
    }
    if (buffer->last_iframe_idx >= 0) {
        buffer->index_to_read = buffer->last_iframe_idx;
        buffer->remaining_count = (buffer->index_to_write + buffer->capacity - buffer->index_to_read) % buffer->capacity;
        if (buffer->remaining_count <= _MAX_BACKWARD_FRAME_NUM_) {
            return 0;
        }
    }
    buffer->index_to_read = -1;
    buffer->remaining_count = 0;

    return 0;
}

uint8_t activate_frame_buffer(st_frame_buffer *buffer) {
    uint8_t retval = 1;
    pthread_mutex_lock(&(buffer->lock));
    retval = _activate_frame_buffer(buffer);
    pthread_mutex_unlock(&(buffer->lock));

    return retval;
}

uint8_t deactivate_frame_buffer(st_frame_buffer *buffer) {
    uint8_t retval = 1;
    pthread_mutex_lock(&(buffer->lock));
    if (buffer->status == BUFFER_STATUS_ACTIVE || buffer->status == BUFFER_STATUS_OVERFLOW) {
        buffer->status = BUFFER_STATUS_STANDBY;
        retval = 0;
    }
    pthread_mutex_unlock(&(buffer->lock));

    return retval;
}

void _set_frame(st_frame_buffer *buffer, int offset, st_frame_info *frame) {
    if (buffer->frames[offset] != NULL) {
        free(buffer->frames[offset]->buffer);
        free(buffer->frames[offset]);
    }
    buffer->frames[offset] = frame;
}

uint8_t _append_frame(st_frame_buffer *buffer, st_frame_info *frame) {
    if (buffer->capacity == 0) {
        _free_frame(frame);
        return APPEND_FRAME_FAILED;
    }
    if (buffer->status == BUFFER_STATUS_OVERFLOW) {
        _free_frame(frame);
        return APPEND_FRAME_OVERFLOW;
    }
    _set_frame(buffer, buffer->index_to_write, frame);
    // overflow next_to_last_iframe_idx
    if (buffer->index_to_write == buffer->next_to_last_iframe_idx) {
        buffer->next_to_last_iframe_idx = -1;
    }
    // overflow last_iframe_idx
    if (buffer->index_to_write == buffer->last_iframe_idx) {
        buffer->last_iframe_idx = -1;
    }
    // update iframe related variables
    if (frame->frametype == 1) {
        buffer->next_to_last_iframe_idx = buffer->last_iframe_idx;
        buffer->last_iframe_idx = buffer->index_to_write;
        if (buffer->index_to_read < 0) {
            // for STANDBY status, it doesn't have any impact, because they will be reset
            buffer->index_to_read = buffer->last_iframe_idx;
            buffer->remaining_count = 0;
        }
    }
    buffer->index_to_write = (buffer->index_to_write + 1) % buffer->capacity;
    if (buffer->status == BUFFER_STATUS_STANDBY) {
        return APPEND_FRAME_SUCCESS;
    }
    if (buffer->index_to_read < 0) {
        // no iframe yet
        return APPEND_FRAME_SUCCESS;
    }
    // update read related variables
    buffer->remaining_count++;
    if (buffer->remaining_count < buffer->capacity) {
        return APPEND_FRAME_SUCCESS;
    }
    // overflow index_to_read: index_to_write == index_to_read, buffer is full, but not really overflow
    buffer->status = BUFFER_STATUS_OVERFLOW;

    return APPEND_FRAME_OVERFLOW;
}

st_frame_info *_copy_frame(st_frame_info *frame) {
    st_frame_info *copy;
    if ((copy = calloc(1, sizeof(st_frame_info))) == NULL) {
        return NULL;
    }
    if ((copy->buffer = malloc(frame->size)) == NULL) {
        free(copy);
        copy = NULL;
        return NULL;
    }
    memcpy(copy->buffer, frame->buffer, frame->size);
    memcpy(copy->hash, frame->hash, IOECR_HASH_LENGTH);
    copy->size = frame->size;
    copy->channel = frame->channel;
    copy->codecid = frame->codecid;
    copy->frametype = frame->frametype;
    copy->pts = frame->pts;
    copy->version = frame->version;
    copy->encryptID = frame->encryptID;
    return copy;
}

uint8_t append_frame(st_frame_buffer *buffer, st_frame_info *frame) {
    uint8_t retval;
    st_frame_info *copy = _copy_frame(frame);
    if (copy == NULL) {
        return APPEND_FRAME_FAILED;
    }
    pthread_mutex_lock(&(buffer->lock));
    retval = _append_frame(buffer, copy);
    if (retval == APPEND_FRAME_FAILED || retval == APPEND_FRAME_OVERFLOW) {
        copy = NULL;
    }
    pthread_mutex_unlock(&(buffer->lock));
    return retval;
}

uint8_t _pop_frame(st_frame_buffer *buffer, st_frame_info **frame) {
    *frame = NULL;
    if (buffer->status == BUFFER_STATUS_STANDBY) {
        return POP_FRAME_NOT_ACTIVE;
    }
    if (buffer->remaining_count == 0 || buffer->index_to_read < 0) {
        if (buffer->status == BUFFER_STATUS_OVERFLOW) {
            return POP_FRAME_NO_DATA_AND_OVERFLOW;
        }
        return POP_FRAME_NO_DATA;
    }
    *frame = buffer->frames[buffer->index_to_read];
    if (*frame == NULL) {
        return POP_FRAME_FAIL_TO_COPY;
    }
    buffer->frames[buffer->index_to_read] = NULL;
    if (buffer->index_to_read == buffer->next_to_last_iframe_idx) {
        buffer->next_to_last_iframe_idx = -1;
    }
    if (buffer->index_to_read == buffer->last_iframe_idx) {
        buffer->next_to_last_iframe_idx = -1;
        buffer->last_iframe_idx = -1;
    }
    buffer->index_to_read = (buffer->index_to_read + 1) % buffer->capacity;
    buffer->remaining_count--;
    if (buffer->status == BUFFER_STATUS_OVERFLOW) {
        return POP_FRAME_SUCCESS_BUT_OVERFLOW;
    }
    return POP_FRAME_SUCCESS;
}

uint8_t pop_frame(st_frame_buffer *buffer, st_frame_info **frame) {
    uint8_t retval;
    pthread_mutex_lock(&(buffer->lock));
    retval = _pop_frame(buffer, frame);
    pthread_mutex_unlock(&(buffer->lock));
    return retval;
}
