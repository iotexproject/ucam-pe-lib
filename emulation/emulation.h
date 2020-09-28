#ifndef _IOECR_EMULATION_H_
#define _IOECR_EMULATION_H_
#include <pthread.h>
#include <stdio.h>

#include "ioecr/lib.h"

#define PES_HEADER  36

// Codec ID
#define MEDIA_CODEC_UNKNOWN      0x00
#define MEDIA_CODEC_VIDEO_MPEG4  0x4C
#define MEDIA_CODEC_VIDEO_H263   0x4D
#define MEDIA_CODEC_VIDEO_H264   0x4E
#define MEDIA_CODEC_VIDEO_MJPEG  0x4F

#define MEDIA_CODEC_AUDIO_G711  0x8A
#define MEDIA_CODEC_AUDIO_ADPCM 0x8B
#define MEDIA_CODEC_AUDIO_PCM	0x8C
#define MEDIA_CODEC_AUDIO_SPEEX 0x8D
#define MEDIA_CODEC_AUDIO_MP3   0x8E
#define MEDIA_CODEC_AUDIO_G726  0x8F

typedef enum {
	E_VIDEO_PB_FRAME = 0,
	E_VIDEO_I_FRAME,
	E_VIDEO_TS_FRAME,
	E_AUDIO_FRAME,
	E_MEDIA_FRAME_TYPE_MAX
} MEDIA_FRAME_TYPE_E;

typedef struct {
    FILE* fp;
    int CurFramePosition;
    unsigned char* pFrameAddr;
    int pes_count;
    unsigned long time_start;
    unsigned long latest_pts;
    unsigned long start_pts;
    int alive;
} st_emu_context;

int Emulation_get_frame_info(st_frame_info* frameinfo);

int Emulation_Start(st_emu_context* ctx, pthread_t *thread_id);
void Emulation_Stop(st_emu_context* ctx);
int Emulation_get_credential(st_credential *c);
int Emulation_release_credential(st_credential *c);
void Emulation_send_frames(st_emu_context *ctx);

#endif
