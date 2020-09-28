#ifndef _IO_ECR_RECORDER_H_
#define _IO_ECR_RECORDER_H_
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

#include "lib.h"

/**
 * @brief Enable recorder to upload video to cloud
 * @note
 * @retval 0: success
 *         others: failed
 */
int enable_upload();

/**
 * @brief Disable recorder to upload video to cloud
 * @note
 * @retval 0: success
 *         others: failed
 */
int disable_upload();

/**
 * @brief Check whether video upload is disabled
 * @note
 * @retval 0: enabled
 *         1: disabled
 */
uint8_t upload_disabled();

/**
 * @brief  Initialize IOECR library context for recording.
 * @note   This function registers callbacks, and initializes internal components.
 * @param  get_frame: get frame function call back.
 * @param  release_frame: release frame function call back.
 * @retval 0 : success
 *         <0: error code returned from internal components, such as,log, context's init routines.
 */
int initialize_recorder();

int initialize_recorder_with_customized_uploader(
  cb_get_credential get_credential,
  cb_release_credential release_credential,
  cb_get_uploader get_uploader,
  cb_release_uploader release_uploader,
  cb_process_frame process_frame);

/**
 * @brief  Release interal resources hold by ioecr library.
 * @note
 * @retval None
 */
void release_recorder();

/**
 * @brief  Start recording
 * @note   This is non-blocking call, whcih creates a joinable main thread and return
 *         the thread ID.
 *         The main thread will further create other threads to get token and
 *         upload address, and eventually upload video and snapshot frames
 *         to the cloud. After those thread are done, the main thread join them. The caller
 *         of this function is responsible to join the main thread with the thread ID
 *         returned in pthreadid.
 * @param  pthreadid: return the created thread ID.
 * @retval 0: success
 *         1: callbacks are not registerd
 *         2: thread creation fails
 */
int start_recording(pthread_t* pthreadid);

void receive_frame(st_frame_info *frame);

#endif
