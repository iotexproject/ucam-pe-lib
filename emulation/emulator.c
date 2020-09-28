/* Generic */
#include <mbedtls/aes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <curl/curl.h>

#include "ioecr/hmac.h"
#include "ioecr/lib.h"
#include "emulation.h"
#include "memleak.h"

extern st_emu_context g_emu_ctx;

int main(int argc, char **argv) {
  dbg_init(10);
  dbg_catch_sigsegv();

  int key_status, i = 0;
  pthread_t otaThreadId, recordThreadId, emutation_thread_id;
  void *ret;
  uint8_t version[10];
  uint32_t nonce;

  unsigned char enc_key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00};
  static unsigned char zero_key_hash[HMAC_OUT_LENGTH] = {0xa, 0x33, 0x47, 0x79, 0xb5, 0x1c, 0x8f, 0x2e, 0x60, 0x3f, 0xc2, 0x78, 0x60, 0x67, 0xea, 0x40, 0x4e, 0x16, 0xc0, 0x8f};
  printf("Start emulation...\n");

  printf("Download OTA: %d\n", ioecr_ota("https://gateway.pinata.cloud/ipfs/QmYztxy1mxXiWcagc24mgGvMynAKY7ZJouTpjtnzeYsGcc/update.bin", "./update.bin", &otaThreadId));
  pthread_join(otaThreadId, &ret);
  printf("joined: %d\n", (uint32_t)ret);

  // Prepare ioecr
  ioecr_get_version(version,10);
  printf("Version %s\n", version);

  // register callbacks
  if (ioecr_initialize_encryptor() != 0) {
    printf("failed to initialize encryptor\n");
    return -1;
  }
  if (ioecr_initialize_recorder(Emulation_get_credential, Emulation_release_credential) != 0) {
    printf("failed to initialize recorder\n");
    return -1;
  }
  printf("callbacks registered\n");
  // set encryption key
  key_status = ioecr_check_encryption_key(zero_key_hash, 20, &nonce);
  printf("key_status %d\n", key_status);
  if (key_status & IOECR_KEY_E_LOCK) {
    printf("lib failed to obtain lock\n");
    return -1;
  }
  if ((key_status & IOECR_KEY_ENABLED) == 0) {
    // encryption disabled, set the key
    ioecr_set_encryption_key(10101011, enc_key, 16, zero_key_hash, 20);
    key_status = ioecr_check_encryption_key(zero_key_hash, 20, &nonce);
    printf("new record key set with nonce %d\n", nonce);
  } else {
    if (nonce != 10101011) {
      printf("nonce is wrong\n");
      return -1;
    }
    printf("record key already set, with nonce %d\n", nonce);
  }
  printf("upload disabled: %d\n", ioecr_upload_disabled());
  printf("disable upload: %d\n", ioecr_disable_upload());
  printf("upload disabled: %d\n", ioecr_upload_disabled());
  printf("enable upload: %d\n", ioecr_enable_upload());
  printf("upload disabled: %d\n", ioecr_upload_disabled());

  // Setup emulation
  if (0 != Emulation_Start(&g_emu_ctx, &emutation_thread_id)) {
    printf("missing /tmp/test.pes\n");
    return -1;
  }
  while (i++ < 10) {
    printf("==================\nIter: %d\n", i);
    dbg_mem_stat();
    dbg_heap_dump("");
    // start a thread for recording
    if (ioecr_start_recording(&recordThreadId) != 0) {
      printf("failed to start recording\n");
      break;
    }
    printf("cloud record started %d\n", (uint32_t)recordThreadId);
    // wait recording thread to complete
    pthread_join(recordThreadId, &ret);
    printf("joined: %d\n", (uint32_t)ret);
    if (ret != NULL) {
      printf("thread exits with error %d\n", (uint32_t)ret);
    } else {
      printf("thread exits with no error\n");
    }
  }
  // aes_test();
  ioecr_release_recorder();
  ioecr_release_encryptor();
  // Stop emulation
  Emulation_Stop(&g_emu_ctx);
  pthread_join(emutation_thread_id, &ret);
  if (ret != NULL) {
    printf("emulation thread join failed %d\n", (int)ret);
  } else {
    printf("emulation thread joined\n");
  }
  dbg_mem_stat();
  dbg_heap_dump("");
  return 0;
}
