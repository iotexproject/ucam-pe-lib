#ifndef _IOECR_UPLOADER_H_
#define _IOECR_UPLOADER_H_

#include <stdint.h>
#include <time.h>

#include "lib.h"
#include "upload_data.h"

#define UPLOADER_STATUS_ALIVE 0u
#define UPLOADER_STATUS_DONE 1u
#define UPLOADER_STATUS_ERROR 2u

#define MAX_VIDEO_CACHE_SIZE 250000
#define MAX_NUM_OF_SNAPSHOTS 10
#define MAX_RECORD_TIME 60000

// define callback functions
int get_uploader(void **uploader, st_credential *credential);
int prepare_cert();
void release_uploader(void **uploader);
void process_frame(void *uploader, void *frame);
uint8_t get_uploader_status(void *uploader);

#endif