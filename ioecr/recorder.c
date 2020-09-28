/* Generic */
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "frame_buffer.h"
#include "key_store.h"
#include "log.h"
#include "config.h"
#include "uploader.h"
#include "recorder.h"

#ifndef _UCAM_LOG_RECORDER_FILE_
#define _UCAM_LOG_RECORDER_FILE_ "/tmp/ucam-recorder.log"
#endif

typedef struct {
    cb_get_credential get_credential;
    cb_release_credential release_credential;
    cb_get_uploader get_uploader;
    cb_release_uploader release_uploader;
    cb_process_frame process_frame;
    pthread_mutex_t lock;
    void *uploader;
    uint8_t upload_disabled;
    st_frame_buffer buffer;
    int8_t initialized;
} st_recorder;

static st_recorder g_recorder;
static pthread_once_t g_recorder_init = PTHREAD_ONCE_INIT;

void *thread_exit_with_error(const char *error, void *errorcode) {
    log_error(error);
    pthread_exit(errorcode);
    return NULL;
}

int prepare_recorder(st_recorder *recorder) {
    recorder->uploader = NULL;
    return activate_frame_buffer(&(recorder->buffer));
}

void reset_recorder(st_recorder *recorder) {
    log_info("reset uploader");
    if (recorder->uploader != NULL) {
        recorder->release_uploader(&(recorder->uploader));
        recorder->uploader = NULL;
    }
    deactivate_frame_buffer(&(recorder->buffer));
    pthread_mutex_unlock(&(recorder->lock));
}

void receive_frame(st_frame_info *frame) {
    if (frame == NULL) {
        return;
    }
    switch (append_frame(&(g_recorder.buffer), frame)) {
    case APPEND_FRAME_FAILED:
        log_warn("failed to append frame");
        break;
    case APPEND_FRAME_OVERFLOW:
        log_debug("frame buffer overflow");
        break;
    }
}

enum THREAD_EXIT_CODE {
  THREAD_EXIT_E_OK = 0,
  THREAD_EXIT_E_LOCK,
  THREAD_EXIT_E_MALLOC,
  THREAD_EXIT_E_FB_INIT,
  THREAD_EXIT_E_GET_ADDR,
  THREAD_EXIT_E_PRODUCER,
};

void callback_process_frame(st_recorder *recorder, st_frame_info *frame) {
    recorder->process_frame(recorder->uploader, frame);
}

#define UNUSED(x) (void)(x)
void *main_thread(void *arg) {
    st_frame_info *frame = NULL;
    st_credential credential;
    UNUSED(arg);
    if (pthread_mutex_trylock(&g_recorder.lock) != 0) {
        return thread_exit_with_error("Thread is busy. main thread exits.\n", (void *)THREAD_EXIT_E_LOCK);
    }
    log_info("prepare a new record");
    if (prepare_recorder(&g_recorder) != 0) {
        reset_recorder(&g_recorder);
        return thread_exit_with_error("failed to prepare recorder.\n", (void *)THREAD_EXIT_E_FB_INIT);
    }
    if (g_recorder.get_credential(&credential) != 0) {
        reset_recorder(&g_recorder);
        return thread_exit_with_error("failed to get credential.\n", (void *)THREAD_EXIT_E_FB_INIT);
    }
    log_info("create uploader");
    if (g_recorder.get_uploader(&(g_recorder.uploader), &credential) != 0) {
        g_recorder.release_credential(&credential);
        reset_recorder(&g_recorder);
        return thread_exit_with_error("failed to create uploader.\n", (void *)THREAD_EXIT_E_FB_INIT);
    }
    g_recorder.release_credential(&credential);
    log_info("uploader created");

    // consumer mode
    while (1) {
        switch (pop_frame(&(g_recorder.buffer), &frame)) {
        case POP_FRAME_SUCCESS_BUT_OVERFLOW:
            log_debug("some frame(s) was dropped.");
            // fallthrough
        case POP_FRAME_SUCCESS:
            callback_process_frame(&g_recorder, frame);
            free(frame->buffer);
            free(frame);
            frame = NULL;
            nanosleep((const struct timespec[]){{0, 1e7L}}, NULL); // sleep and wait for producer
            break;
        case POP_FRAME_NO_DATA_AND_OVERFLOW:
            callback_process_frame(&g_recorder, NULL);
            nanosleep((const struct timespec[]){{0, 1e8L}}, NULL); // sleep and wait for producer
            break;
        case POP_FRAME_NO_DATA:
            nanosleep((const struct timespec[]){{0, 1e8L}}, NULL); // sleep and wait for producer
            break;
        case POP_FRAME_FAIL_TO_COPY:
            // fallthrough
        case POP_FRAME_NOT_ACTIVE:
            reset_recorder(&g_recorder);
            return thread_exit_with_error("unexpected status.\n", (void *)THREAD_EXIT_E_PRODUCER);
        }
        switch (get_uploader_status(g_recorder.uploader)) {
        case UPLOADER_STATUS_ALIVE:
            break;
        case UPLOADER_STATUS_DONE:
            reset_recorder(&g_recorder);
            pthread_exit(NULL);
            return NULL;
        default: // UPLOADER_STATUS_ERROR:
            reset_recorder(&g_recorder);
            log_warn("failed to upload.");
            pthread_exit((void *)1);
            return NULL;
        }
    }
}


int turn_off_upload(uint8_t off) {
    FILE *fp;
    pthread_mutex_lock(&g_recorder.lock);
    if ((fp = fopen(RECORDER_CONFIG_FILE, "we")) == NULL) {
        pthread_mutex_unlock(&g_recorder.lock);
        log_error("config file %s open error!\n", RECORDER_CONFIG_FILE);
        return -1;
    }
    if (fwrite(&off, sizeof(uint8_t), 1, fp) != 1) {
        pthread_mutex_unlock(&g_recorder.lock);
        fclose(fp);
        fp = NULL;
        log_error("failed to write config");
        return -1;
    }
    fclose(fp);
    fp = NULL;
    g_recorder.upload_disabled = off;
    pthread_mutex_unlock(&g_recorder.lock);
    return 0;
}

int enable_upload() {
    return turn_off_upload(0);
}

int disable_upload() {
    return turn_off_upload(1);
}

uint8_t upload_disabled() {
    return g_recorder.upload_disabled;
}

/*
  start_recording()
*/
int start_recording(pthread_t *pthreadid) {
    // check callback
    if (g_recorder.get_uploader == NULL || g_recorder.release_uploader == NULL || g_recorder.process_frame == NULL) {
        log_error("Callbacks are not registed!\n");
        return 1;
    }
    if (g_recorder.upload_disabled) {
        return 0;
    }

    if (pthread_create(pthreadid, NULL, main_thread, (void *)NULL) != 0) {
        log_error("thread creation fail\n");
        return 2;
    }
    return 0;
}

int initialize_recorder(cb_get_credential get_credential, cb_release_credential release_credential) {
    return initialize_recorder_with_customized_uploader(
        get_credential,
        release_credential,
        get_uploader,
        release_uploader,
        process_frame);
}

void _initialize_lock() {
    // ignore error handling
    // log_init(_UCAM_LOG_RECORDER_FILE_);
    // log_set_level(LOG_WARN);
    log_set_level(LOG_INFO);
    log_info("initialize lock %d", g_recorder.initialized);
    // g_recorder.initialized = 0;
    pthread_mutex_init(&(g_recorder.lock), NULL);
}

int initialize_recorder_with_customized_uploader(
    cb_get_credential get_credential,
    cb_release_credential release_credential,
    cb_get_uploader get_uploader,
    cb_release_uploader release_uploader,
    cb_process_frame process_frame) {
    int ret;
    FILE *fp;
    if (!get_uploader || !release_uploader || !process_frame) {
        fprintf(stderr, "Callbacks can't be NULL!\n");
        return -1;
    }
    pthread_once(&g_recorder_init, _initialize_lock);
    log_warn("try to lock %d", getpid());
    pthread_mutex_lock(&g_recorder.lock);
    if (g_recorder.initialized != 0) {
        log_warn("already initialized");
        pthread_mutex_unlock(&g_recorder.lock);
        return -1;
    }
    log_warn("initialize recorder in thread %d %d %d", pthread_self(), &g_recorder, g_recorder.initialized);
    g_recorder.get_credential = get_credential;
    g_recorder.release_credential = release_credential;
    g_recorder.get_uploader = get_uploader;
    g_recorder.release_uploader = release_uploader;
    g_recorder.process_frame = process_frame;
    g_recorder.uploader = NULL;
    if (prepare_cert() != 0) {
        log_error("failed to prepare cert file");
    }
    if ((fp = fopen(RECORDER_CONFIG_FILE, "re")) != NULL) {
        if (fread(&g_recorder.upload_disabled, sizeof(uint8_t), 1, fp) != 1) {
            log_error("failed to read recorder config %s\n", RECORDER_CONFIG_FILE);
        }
        fclose(fp);
        fp = NULL;
    }
    log_info("video upload disabled: %d\n", g_recorder.upload_disabled);

    if ((ret = init_frame_buffer(&(g_recorder.buffer))) != 0) {
        pthread_mutex_unlock(&g_recorder.lock);
        return ret;
    }
    g_recorder.initialized = 1;
    log_warn("recorder initialized %d %d", &g_recorder, g_recorder.initialized);
    pthread_mutex_unlock(&g_recorder.lock);

    return 0;
}

void release_recorder() {
    pthread_mutex_lock(&(g_recorder.lock));
    release_frame_buffer(&(g_recorder.buffer));
    g_recorder.get_credential = NULL;
    g_recorder.release_credential = NULL;
    g_recorder.get_uploader = NULL;
    g_recorder.release_uploader = NULL;
    g_recorder.process_frame = NULL;
    pthread_mutex_unlock(&(g_recorder.lock));
    pthread_mutex_destroy(&(g_recorder.lock));
    log_close_fp();
}
