#include <string.h>
#include <curl/curl.h>

#include "config.h"
#include "encryptor.h"
#include "recorder.h"
#include "uploader.h"

int ioecr_get_version(uint8_t *buf, uint32_t size) {
    if (size <= strlen(VERSION_STRING)) {
        return 1;
    }

    strncpy((char *)buf, VERSION_STRING, size);

    return 0;
}

int ioecr_check_encryption_key(const uint8_t* hash, int length, uint32_t *nonce) {
    return check_key(hash, length, nonce);
};

void ioecr_release_encryptor() {
    release_encryptor();
}

int ioecr_initialize_encryptor() {
    return initialize_encryptor();
}

int ioecr_encrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, uint8_t *key_hash) {
    return encrypt(buffer, buffer_size, nonce_counter, key_hash);
}

int ioecr_decrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, const uint8_t *key_hash) {
    return decrypt(buffer, buffer_size, nonce_counter, key_hash);
}

int ioecr_set_encryption_key(uint32_t nonce, const uint8_t* new_key, int new_key_length, const uint8_t *curr_key_hash, int hash_length) {
    return set_encryption_key(nonce, new_key, new_key_length, curr_key_hash, hash_length);
}

int ioecr_initialize_recorder(
    cb_get_credential get_credential,
    cb_release_credential release_credential) {
    return initialize_recorder(get_credential, release_credential);
}

int ioecr_initialize_upload(
    cb_get_credential get_credential,
    cb_release_credential release_credential) {
    return ioecr_initialize_recorder(get_credential, release_credential);
}

void ioecr_release_recorder() {
    release_recorder();
}

int ioecr_disable_upload() {
    return disable_upload();
}

int ioecr_enable_upload() {
    return enable_upload();
}

uint8_t ioecr_upload_disabled() {
    return upload_disabled();
}

int ioecr_start_recording(pthread_t* pthreadid) {
    return start_recording(pthreadid);
}

void ioecr_receive_frame(st_frame_info *frame) {
    receive_frame(frame);
}

static int progress(void *p, double dltotal, double dlnow, double ultotal, double ulnow) {
    cb_update_ota_progress uap = (cb_update_ota_progress)p;
    if (dltotal >= 1.0) {
        uap(dlnow * 100 / dltotal);
    }
    return 0;
}

typedef struct {
    const char *url;
    const char *save_to;
    cb_write_ota_data write_data;
    cb_update_ota_progress update_progress;
} st_download_ota_param;

void *download_ota(void *arg) {
    st_download_ota_param *param = arg;
    FILE *fp = NULL;
    CURL *curl = NULL;
    CURLcode ret;
    uint8_t disable_ssl_verifier = 0;
    while (disable_ssl_verifier < 2) {
        if ((fp = fopen(param->save_to, "wb")) == NULL) {
            printf("failed to open file %s\n", param->save_to);
            pthread_exit((void *)1);
        }
        if ((curl = curl_easy_init()) == NULL) {
            printf("failed to init curl\n");
            fclose(fp);
            pthread_exit((void *)1);
        }
        curl_easy_setopt(curl, CURLOPT_URL, param->url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, param->write_data);
        if (param->update_progress != NULL) {
            curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress);
            curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, param->update_progress);
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        } else {
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        }
        if (disable_ssl_verifier == 0) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, CA_CERTIF_FILE);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        ret = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);
        if (ret == CURLE_OK) {
            break;
        }
        if (ret != CURLE_PEER_FAILED_VERIFICATION && ret != CURLE_SSL_CACERT_BADFILE) {
            break;
        }
        disable_ssl_verifier++;
    }
    pthread_exit((void *)ret);
}

int ioecr_ota(const char *url, const char *save_to, cb_write_ota_data write_data, cb_update_ota_progress update_progress, pthread_t *pthreadid) {
    st_download_ota_param *param = calloc(1, sizeof(st_download_ota_param));
    param->url = url;
    param->save_to = save_to;
    param->write_data = write_data;
    param->update_progress = update_progress;
    if (pthread_create(pthreadid, NULL, download_ota, (void *)param) != 0) {
        log_error("failed to create thread\n");
        return 1;
    }
    return 0;
}
