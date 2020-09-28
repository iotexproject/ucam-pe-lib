#ifndef _IO_ECR_CONFIG_H_
#define _IO_ECR_CONFIG_H_
#include <stdint.h>
#include <stdio.h>

#define TOKEN_DURATION 2592000

/* File settings */
#define SNAP_SHOT_FILE "/tmp/snapshottemp"
#define VIDEO_REC_FIL0 "/tmp/cloudvideotemp0"
#define VIDEO_REC_FIL1 "/tmp/cloudvideotemp1"

#ifndef ENCRY_KEY_FILE
#ifdef DEVELOP
#define ENCRY_KEY_FILE "./key"
#else
#define ENCRY_KEY_FILE "/etc/conf/key"
#endif
#endif

#ifndef RECORDER_CONFIG_FILE
#ifdef DEVELOP
#define RECORDER_CONFIG_FILE "./recorder.conf"
#else
#define RECORDER_CONFIG_FILE "/etc/conf/recorder.conf"
#endif
#endif

#define ENABLE_VERBOSE_MODE 1

#define VERSION_STRING "0.6.13"

#endif
