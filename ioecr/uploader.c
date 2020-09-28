#include <assert.h>
#include <curl/curl.h>
#include <mbedtls/base64.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hmac.h"
#include "jsmn.h"
#include "log.h"
#include "uploader.h"
#include "upload_cycle_queue.h"

#define __UPLOADER_INTERNAL_STATUS_ALIVE__ 1u
#define __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__ 2u
#define __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__ 4u
#define __UPLOADER_INTERNAL_STATUS_ERROR__ 8u
#define __UPLOADER_INTERNAL_STATUS_OFF__ 16u

#define MAX_SUFFIX_LENGTH 14

#define TOKEN_DURATION 2592000

#define UPLOAD_DATA_ARRAY_SIZE 10

#define VIDEO_FILE_SUFFIX ".dat"
#define INDEX_FILE_SUFFIX "."
#define SNAPSHOT_FILE_SUFFIX ".thumb.dat"

#define POST_PARAM_URL "url"
#define POST_PARAM_TOKEN "token"
#define POST_PARAM_FIELDS "fields"
#define POST_PARAM_CREATE_VIDEO "createPresignedPostVideo"
#define POST_PARAM_CREATE_SNAPSHOT "createPresignedPostSnapshot"
#define POST_PARAM_CREATE_VIDEO_IDX "createPresignedPostVideoIndex"
#define POST_PARAM_CREATE_SNAPSHOT_IDX "createPresignedPostSnapshotIndex"

#define FETCH_PARAMETER_URL_LENGTH 200
#define FETCH_PARAMETER_URL "https://s3-ucam.iotex.io/api-s3-credentials-by-uid"

typedef struct {
    st_upload_parameter snapshot_upload_param;
    st_upload_parameter snapshot_index_upload_param;
    st_upload_parameter video_upload_param;
    st_upload_parameter video_index_upload_param;
    uint8_t *keyhash;
    uint32_t keyhash_size;
    uint8_t video_cache[MAX_VIDEO_CACHE_SIZE];
    uint32_t video_cache_size;
    uint32_t video_count;
    uint32_t snapshot_count;
    uint32_t num_of_snapshots_to_capture;
    uint32_t start_pts;
    uint32_t msecond_recorded;
    uint32_t msecond_to_record;
    st_upload_cycle_queue cq;
    pthread_t upload_data_threadid;

    pthread_mutex_t lock; // lock for status
    uint8_t status;
} st_uploader;

uint8_t _get_uploader_status(st_uploader *uploader) {
    uint8_t status;
    pthread_mutex_lock(&(uploader->lock));
    status = uploader->status;
    pthread_mutex_unlock(&(uploader->lock));

    return status;
}

void _set_uploader_status(st_uploader *uploader, uint8_t new_status) {
    pthread_mutex_lock(&(uploader->lock));
    uploader->status |= new_status;
    pthread_mutex_unlock(&(uploader->lock));
}

int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

char *itoa(unsigned int num, char *str) {
  assert(str != NULL);
  int end = 0, start = 0, remaining = 0;
  char temp;

  if (num == 0) {
    str[end++] = '0';
    str[end] = 0;
    return str;
  }
  while (num != 0) {
    remaining = num % 10;
    str[end++] = remaining + '0';
    num = num / 10;
  }
  str[end] = 0; // Append string terminator
  while (start < end - 1) {
    temp = str[start];
    str[start] = str[end - 1];
    str[end - 1] = temp;
    start++;
    end--;
  }
  return str;
}

uint32_t concat_index_and_suffix(int index, const char *suffix, uint32_t suffix_len, char *output) {
  uint32_t length = suffix_len;
  itoa(index, output);
  length += strlen(output);
  strncat(output, suffix, suffix_len);
  return length;
}

int alphabet_compare(const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len) {
    assert(a != NULL);
    assert(b != NULL);

    int i = 0;
    while (i < a_len && i < b_len) {
        if (a[i] < b[i]) {
            return 1;
        }
        if (a[i] > b[i]) {
            return -1;
        }
        i++;
    }
    if (i == a_len && i == b_len) {
        return 0;
    }
    if (i == a_len) {
        return 1;
    }
    return -1;
}

static void get_signature(const char *uid, uint32_t uid_len, \
                          const char *c_ts, uint32_t c_ts_len, \
                          const char *c_rand, uint32_t c_rand_len, \
                          const char *key, uint32_t key_len, uint8_t signature[20]) {
    uint8_t *joined = malloc(uid_len + c_ts_len + c_rand_len);

    int uid_vs_ts = alphabet_compare((uint8_t *)uid, uid_len, (uint8_t *)c_ts, c_ts_len);
    int uid_vs_rand = alphabet_compare((uint8_t *)uid, uid_len, (uint8_t *)c_rand, c_rand_len);
    int ts_vs_rand = alphabet_compare((uint8_t *)c_ts, c_ts_len, (uint8_t *)c_rand, c_rand_len);

    if (uid_vs_ts >= 0) {
        if (uid_vs_rand >= 0) {
            memcpy(joined, uid, uid_len);
            if (ts_vs_rand >= 0) {
                memcpy(joined + uid_len, c_ts, c_ts_len);
                memcpy(joined + uid_len + c_ts_len, c_rand, c_rand_len);
            } else {
                memcpy(joined + uid_len, c_rand, c_rand_len);
                memcpy(joined + uid_len + c_rand_len, c_ts, c_ts_len);
            }
        } else {
            memcpy(joined, c_rand, c_rand_len);
            memcpy(joined + c_rand_len, uid, uid_len);
            memcpy(joined + c_rand_len + uid_len, c_ts, c_ts_len);
        }
    } else {
        if (ts_vs_rand >= 0) {
            memcpy(joined, c_ts, c_ts_len);
            if (uid_vs_rand >= 0) {
                memcpy(joined + c_ts_len, uid, uid_len);
                memcpy(joined + c_ts_len + uid_len, c_rand, c_rand_len);
            } else {
                memcpy(joined + c_ts_len, c_rand, c_rand_len);
                memcpy(joined + c_ts_len + c_rand_len, uid, uid_len);
            }
        } else {
            memcpy(joined, c_rand, c_rand_len);
            memcpy(joined + c_rand_len, c_ts, c_ts_len);
            memcpy(joined + c_rand_len + c_ts_len, uid, uid_len);
        }
    }
    hmac_sha1(joined, uid_len + c_rand_len + c_ts_len, (uint8_t *)key, key_len, signature);
    free(joined);
    joined = NULL;
}

static int encode_signature(uint8_t sig[20], char *encoded, uint32_t *len) {
    uint8_t sig_base64[32];
    size_t sig_base64_len;
    int i;
    // base64 encode of 20-byte is at most 28 bytes long
    if (mbedtls_base64_encode(sig_base64, 32, &sig_base64_len, sig, 20) != 0) {
        return 1;
    }
    for (i = 0; i < sig_base64_len; i++) {
        *len += 3;
        switch (sig_base64[i]) {
        case '+':
            *encoded++ = '%';
            *encoded++ = '2';
            *encoded++ = 'B';
            break;
        case '/':
            *encoded++ = '%';
            *encoded++ = '2';
            *encoded++ = 'F';
            break;
        case '=':
            *encoded++ = '%';
            *encoded++ = '3';
            *encoded++ = 'D';
            break;
        default:
            *encoded++ = sig_base64[i];
            *len -= 2;
        }
    }
    *encoded = 0;
    return 0;
}

int compose_fetch_parameter_url(const char *uid, uint32_t uid_len, time_t ts, const char *key, uint32_t key_len, char *url, uint32_t max_url_len) {
    uint8_t i, sig[20];
    char c_ts[20], c_rand[3];
    const char *url_start = url;
    uint32_t c_ts_len = 0, c_rand_len = 0, base_len = strlen(FETCH_PARAMETER_URL), sig_urlencode_len = 0;

    /* Must ends with NULL */
    static const char *keys[] = {
        "?uid=",
        "&rand=",
        "&ts=",
        "&signature=",
        NULL
    };

    const char *values[] = {
        uid,
        c_rand,
        c_ts,
        NULL,
    };
    uint32_t lens[] = {
        uid_len,
        c_rand_len,
        c_ts_len,
        0,
    };

    itoa(ts, c_ts);
    c_ts_len = strlen(c_ts);
    c_ts[c_ts_len] = '0';
    c_ts[c_ts_len + 1] = '0';
    c_ts[c_ts_len + 2] = '0';
    c_ts[c_ts_len + 3] = 0;
    c_ts_len += 3;
    lens[2] = c_ts_len;

    srand(ts);
    itoa(rand() % 99 + 1, c_rand);
    c_rand_len = strlen(c_rand);
    lens[1] = c_rand_len;

    get_signature(uid, uid_len, c_ts, c_ts_len, c_rand, c_rand_len, key, key_len, sig);
    memcpy(url, FETCH_PARAMETER_URL, base_len);
    url += base_len;

    /* Compose key and value */
    for (i = 0; keys[i] && (url - url_start + strlen(keys[i]) < max_url_len); i++) {
        memcpy(url, keys[i], strlen(keys[i]));
        url += strlen(keys[i]);
        if (values[i] && (url - url_start + lens[i] < max_url_len)) {
            memcpy(url, values[i], lens[i]);
            url += lens[i];
        }
    }

    return encode_signature(sig, url, &sig_urlencode_len);
}

char lower_uint8_to_char(uint8_t i) {
    i = i & 0xF;
    if (i <= 9) {
        return '0' + i;
    }
    return 'a' + i - 10;
}

char *uint8_to_str(uint8_t i, char output[2]) {
    output[0] = lower_uint8_to_char(i >> 4);
    output[1] = lower_uint8_to_char(i);
    return output;
}

void free_upload_parameters(st_upload_parameter *param) {
    int i;
    if (param == NULL) {
        return;
    }
    free(param->url);
    param->url = NULL;
    for (i = 0; i < param->size; i++) {
        free(param->names[i]);
        param->names[i] = NULL;
        free(param->values[i]);
        param->values[i] = NULL;
    }
    free(param->names);
    param->names = NULL;
    free(param->values);
    param->values = NULL;
}

typedef struct {
  char *ptr;
  uint32_t len;
} st_post_parameters;

void free_post_parameters(st_post_parameters *param) {
  if (param == NULL) {
    return;
  }
  free(param->ptr);
  param->ptr = NULL;
  param->len = 0;
}

uint32_t cb_get_parameters(void *ptr, uint32_t size, uint32_t nmemb, void *p) {
    st_post_parameters *param = p;
    uint32_t new_len = size * nmemb;
    if (param->ptr == NULL) {
        param->len = 0;
        if ((param->ptr = malloc(new_len + 1)) == NULL) {
            return 0;
        }
    } else {
        // curl may call cb_get_parameters more than one time to send more data
        if ((param->ptr = realloc(param->ptr, param->len + new_len + 1)) == NULL) {
            param->len = 0;
            return 0;
        }
    }
    memcpy(param->ptr + param->len, ptr, new_len);
    param->len += new_len;
    param->ptr[param->len] = 0;
    return new_len;
}

enum HTTP_STATUS {HTTP_OK = 200};
#define JPARSER_MAX_TOKEN_LEN 150

int _form_index_suffix(int count, uint8_t *hash, uint8_t hash_len, char *suffix) {
    uint32_t suffix_len;
    char b[2];
    int i;
    suffix[0] = '.';
    suffix_len = concat_index_and_suffix(count, INDEX_FILE_SUFFIX, strlen(INDEX_FILE_SUFFIX), suffix + 1) + 1;
    if (hash != NULL) {
        for (i = 0; i < hash_len; i++) {
            strncat(suffix + suffix_len + i * 2, uint8_to_str(hash[i], b), 2);
        }
        suffix_len += 2 * hash_len;
    }

    return suffix_len;
}

int upload_snapshot(st_uploader *uploader, uint8_t *data, uint32_t size) {
    st_upload_data *ud = NULL;
    char suffix[MAX_SUFFIX_LENGTH];
    uint32_t suffix_len;
    uint8_t status = _get_uploader_status(uploader);
    if ((status & __UPLOADER_INTERNAL_STATUS_ERROR__) != 0 || (status & __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__) != 0) {
        return -1;
    }
    suffix_len = concat_index_and_suffix(uploader->snapshot_count, SNAPSHOT_FILE_SUFFIX, strlen(SNAPSHOT_FILE_SUFFIX), suffix);

    ud = new_upload_data(&(uploader->snapshot_upload_param), suffix, suffix_len, data, size);
    if (ud != NULL) {
        if (upload_cycle_enqueue(&(uploader->cq), ud) == ENQUE_SUCCESS) {
            uploader->snapshot_count++;
            return 0;
        }
        free_upload_data(ud);
    }
    _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
    return -1;
}

int upload_snapshot_index(st_uploader *uploader) {
    if (uploader->snapshot_count == 0) {
        return 0;
    }
    char suffix[MAX_SUFFIX_LENGTH + 2 * uploader->keyhash_size];
    uint32_t suffix_len = _form_index_suffix(uploader->snapshot_count, uploader->keyhash, uploader->keyhash_size, suffix);
    st_upload_data *ud = new_upload_data(&(uploader->snapshot_index_upload_param), suffix, suffix_len, NULL, 0);
    if (ud == NULL) {
        return -1;
    }
    if (upload_cycle_enqueue(&(uploader->cq), ud) == ENQUE_SUCCESS) {
        return 0;
    }
    free_upload_data(ud);

    return -1;
}

int upload_video(st_uploader *uploader) {
    st_upload_data *ud;
    char suffix[MAX_SUFFIX_LENGTH];
    uint32_t suffix_len;
    uint8_t status = _get_uploader_status(uploader);
    if ((status & __UPLOADER_INTERNAL_STATUS_ERROR__) != 0 || (status & __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__) != 0) {
        return -1;
    }
    suffix_len = concat_index_and_suffix(uploader->video_count, VIDEO_FILE_SUFFIX, strlen(VIDEO_FILE_SUFFIX), suffix);
    ud = new_upload_data(&(uploader->video_upload_param), suffix, suffix_len, uploader->video_cache, uploader->video_cache_size);
    if (ud != NULL) {
        if (upload_cycle_enqueue(&(uploader->cq), ud) == ENQUE_SUCCESS) {
            uploader->video_cache_size = 0;
            uploader->video_count++;
            return 0;
        }
        free_upload_data(ud);
    }
    _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
    return -1;
}

int upload_video_index(st_uploader *uploader) {
    char suffix[MAX_SUFFIX_LENGTH + 2 * uploader->keyhash_size];
    uint32_t suffix_len = _form_index_suffix(uploader->video_count, uploader->keyhash, uploader->keyhash_size, suffix);
    st_upload_data *ud = new_upload_data(&(uploader->video_index_upload_param), suffix, suffix_len, NULL, 0);
    if (ud == NULL) {
        return -1;
    }
    if (post_data(ud) != 0) {
        free_upload_data(ud);
        return -1;
    }
    free_upload_data(ud);

    return 0;
}

void upload_index_files(st_uploader *uploader) {
    uint8_t status = _get_uploader_status(uploader);
    if ((status & __UPLOADER_INTERNAL_STATUS_ERROR__) != 0) {
        return;
    }
    if ((status & __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__) != 0 && uploader->video_count != 0) {
        if (upload_video_index(uploader) != 0) {
            log_error("failed to upload video index file");
            return;
        }
    }
}

void set_snapshot_count(st_uploader *uploader) {
    int i;
    long snapshot_count = 0;
    if (uploader->snapshot_upload_param.url == NULL) {
        _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__);
        return;
    }
    for (i = 0; i < uploader->snapshot_upload_param.size; i++) {
        if (is_parameter(uploader->snapshot_upload_param.names[i], UPLOAD_PARAM_SNAPSHOT_COUNT)) {
            snapshot_count = strtol(uploader->snapshot_upload_param.values[i], NULL, 10);
        }
    }
    log_info("snapshot count: %d\n", snapshot_count);
    if (snapshot_count <= MAX_NUM_OF_SNAPSHOTS && snapshot_count >= 0) {
        uploader->num_of_snapshots_to_capture = (uint32_t)snapshot_count;
        if (uploader->num_of_snapshots_to_capture <= uploader->snapshot_count) {
            uint8_t status = _get_uploader_status(uploader);
            if ((status & __UPLOADER_INTERNAL_STATUS_ERROR__) == 0 && (status & __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__) == 0) {
                if (upload_snapshot_index(uploader) != 0) {
                    log_error("failed to upload snapshot index file");
                    _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
                    return;
                }
            }
            _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__);
        }
    }
}

void set_video_duration(st_uploader *uploader) {
    int i;
    long record_duration = 0;
    if (uploader->video_upload_param.url == NULL) {
        _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__);
        return;
    }
    for (i = 0; i < uploader->video_upload_param.size; i++) {
        if (is_parameter(uploader->video_upload_param.names[i], UPLOAD_PARAM_VIDEO_DURATION)) {
            record_duration = strtol(uploader->video_upload_param.values[i], NULL, 10) * 1e3;
        }
    }
    log_info("video duration: %d\n", record_duration);
    if (record_duration >= 0 && record_duration <= MAX_RECORD_TIME) {
        uploader->msecond_to_record = (uint32_t)record_duration;
        if (uploader->msecond_to_record <= uploader->msecond_recorded && uploader->status == UPLOADER_STATUS_ALIVE) {
            _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__);
        }
    }
}

int parse_post_parameters(st_uploader *uploader, st_post_parameters *post_param) {
    jsmn_parser jsmnp;
    jsmntok_t t[JPARSER_MAX_TOKEN_LEN];
    st_upload_parameter *active_param = NULL;
    int i = 1, ifield, r;

    jsmn_init(&jsmnp);
    r = jsmn_parse(&jsmnp, post_param->ptr, post_param->len, t,
                    sizeof(t) / sizeof(t[0]));
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        return -1;
    }
    while (i < r) {
        if (jsoneq(post_param->ptr, &t[i], POST_PARAM_CREATE_VIDEO) == 0) {
            active_param = &(uploader->video_upload_param);
        } else if (jsoneq(post_param->ptr, &t[i], POST_PARAM_CREATE_SNAPSHOT) == 0) {
            active_param = &(uploader->snapshot_upload_param);
        } else if (jsoneq(post_param->ptr, &t[i], POST_PARAM_CREATE_VIDEO_IDX) == 0) {
            active_param = &(uploader->video_index_upload_param);
        } else if (jsoneq(post_param->ptr, &t[i], POST_PARAM_CREATE_SNAPSHOT_IDX) == 0) {
            active_param = &(uploader->snapshot_index_upload_param);
        }
        if (active_param != NULL && strncmp("null", post_param->ptr + t[i + 1].start, t[i+1].end - t[i + 1].start) != 0) {
            while (i < r) {
                if (jsoneq(post_param->ptr, &t[i], POST_PARAM_URL) == 0) {
                    active_param->url = strndup(post_param->ptr + t[i + 1].start, t[i + 1].end - t[i + 1].start);
                    i++;
                }
                if (jsoneq(post_param->ptr, &t[i], POST_PARAM_FIELDS) == 0) {
                    active_param->size = t[i + 1].size;
                    active_param->names = malloc(sizeof(char *) * active_param->size);
                    active_param->values = malloc(sizeof(char *) * active_param->size);
                    i += 2;
                    for (ifield = 0; ifield < active_param->size; ifield++) {
                        active_param->names[ifield] = strndup((post_param->ptr + t[i].start), t[i].end - t[i].start);
                        active_param->values[ifield] = strndup((post_param->ptr + t[i + 1].start), t[i + 1].end - t[i + 1].start);
                        i += 2;
                    }
                    break;
                }
                i++;
            }
            active_param = NULL;
        } else {
            i++;
        }
    }
    set_snapshot_count(uploader);
    set_video_duration(uploader);
    return 0;
}

int fetch_parameters(st_uploader *uploader, st_credential *credential) {
    CURLcode ret;
    CURL *hnd;
    char url[FETCH_PARAMETER_URL_LENGTH];
    st_post_parameters post_param = {};
    time_t now;
    time(&now);
    uploader->snapshot_upload_param.url = NULL;
    uploader->snapshot_index_upload_param.url = NULL;
    uploader->video_upload_param.url = NULL;
    uploader->video_index_upload_param.url = NULL;

    if (compose_fetch_parameter_url(
        credential->uid,
        credential->uid_length,
        now,
        credential->password,
        credential->password_length,
        url,
        sizeof(url)) != 0) {
        return -1;
    }
    if ((hnd = curl_easy_init()) == NULL) {
        return -1;
    }
    curl_easy_setopt(hnd, CURLOPT_URL, url);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(hnd, CURLOPT_CAINFO, CA_CERTIF_FILE);
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, cb_get_parameters);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &post_param);
    ret = curl_easy_perform(hnd);

    // check HTTP status code
    long response_code;
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &response_code);

    curl_easy_cleanup(hnd);
    hnd = NULL;

log_error("response of %s %d\n", url, response_code);
    if (response_code != HTTP_OK || ret != 0) {
        free_post_parameters(&post_param);
        return -1;
    }
    if (post_param.ptr == NULL || post_param.len == 0) {
        return -1;
    }
    if (parse_post_parameters(uploader, &post_param) == 0) {
        free_post_parameters(&post_param);
        return 0;
    }
    free_post_parameters(&post_param);
    return -1;
}

#define CA_CERTIF_DATA "-----BEGIN CERTIFICATE-----\n\
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n\
RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\n\
VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX\n\
DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y\n\
ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy\n\
VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr\n\
mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr\n\
IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK\n\
mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu\n\
XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy\n\
dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye\n\
jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1\n\
BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\n\
DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92\n\
9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx\n\
jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0\n\
Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz\n\
ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS\n\
R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\n\
-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\n\
MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB\n\
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl\n\
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV\n\
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAw\n\
MjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV\n\
BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU\n\
aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy\n\
dGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\n\
AoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B\n\
3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkY\n\
tJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+bJz/\n\
Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2\n\
VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT\n\
79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6\n\
c0Plfg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmT\n\
Yo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97l\n\
c6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4ee\n\
UB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeE\n\
Hg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd\n\
BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8G\n\
A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPF\n\
Up/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KO\n\
VWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3\n\
ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs\n\
8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR\n\
iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYze\n\
Sf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZ\n\
XHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/\n\
qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRB\n\
VXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGwsAvgnEzDHNb842m1R0aB\n\
L6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfG\n\
jjxDah2nGN59PRbxYvnKkKj9\n\
-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\n\
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n\
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n\
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n\
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n\
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n\
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n\
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n\
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n\
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n\
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n\
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n\
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n\
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n\
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n\
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n\
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n\
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n\
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n\
-----END CERTIFICATE-----"

// consumer of upload_cycle_queue
void *start_upload_data(void *arg) {
    uint8_t status;
    st_uploader *uploader = (st_uploader *)arg;
    st_upload_data *ud;
    while (1) {
        status = _get_uploader_status(uploader);
        if ((status & __UPLOADER_INTERNAL_STATUS_ERROR__) != 0) {
            pthread_exit((void *)1);
            return NULL;
        }
        switch (upload_cycle_dequeue(&(uploader->cq), &ud)) {
        case DEQUE_SUCCESS:
            // nanosleep((const struct timespec[]){{30, 1e6L}}, NULL); // sleep and wait for producer
            if (post_data(ud) != 0) {
                _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
            }
            free_upload_data(ud);
            ud = NULL;
            break;
        case DEQUE_NO_DATA:
            if (
                ((status & __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__) != 0 &&
                (status & __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__) != 0) ||
                (status & __UPLOADER_INTERNAL_STATUS_OFF__) != 0
            ) {
                pthread_exit(NULL);
                return NULL;
            }
            nanosleep((const struct timespec[]){{2, 0L}}, NULL); // sleep and wait for producer
            break;
        default: // DEQUE_SUCCESS_WITH_DROP:
            log_error("upload queue overflows");
            _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
            free_upload_data(ud);
            ud = NULL;
            pthread_exit((void *)2);
            return NULL;
        }
    }
    pthread_exit(NULL);
}

int prepare_cert() {
    FILE *fp = NULL;
    if ((fp = fopen(CA_CERTIF_FILE, "re")) == NULL) {
        if ((fp = fopen(CA_CERTIF_FILE, "we")) == NULL) {
            return 1;
        }
        fwrite(CA_CERTIF_DATA, 1, strlen(CA_CERTIF_DATA), fp);
    }
    fclose(fp);
    return 0;
}

int get_uploader(void **arg, st_credential *credential) {
    st_uploader **uploader = (st_uploader **)arg;
    if (prepare_cert() != 0) {
        log_error("failed to prepare cert file");
        return 1;
    }
    *uploader = calloc(1, sizeof(st_uploader));
    if (*uploader == NULL) {
        log_error("failed to malloc uploader space");
        return 1;
    }
    (*uploader)->keyhash = NULL;
    (*uploader)->keyhash_size = 0;
    (*uploader)->num_of_snapshots_to_capture = MAX_NUM_OF_SNAPSHOTS;
    (*uploader)->msecond_to_record = MAX_VIDEO_CACHE_SIZE;
    if (init_upload_cycle_queue(&((*uploader)->cq), 10) != 0) {
        log_error("failed to uploader cycle queue");
        return 1;
    }
    if (fetch_parameters(*uploader, credential) != 0) {
        log_error("failed to fetch credential");
        return 1;
    }
    if (pthread_mutex_init(&((*uploader)->lock), NULL) != 0) {
        log_error("failed to init uploader lock");
        return 1;
    }
    if (pthread_create(&((*uploader)->upload_data_threadid), NULL, start_upload_data, (void *)(*uploader)) != 0) {
        log_error("failed to create upload thread");
        return 1;
    }
    _set_uploader_status(*uploader, __UPLOADER_INTERNAL_STATUS_ALIVE__);

    return 0;
}

void release_uploader(void **arg) {
    void *ret;
    uint8_t status;
    st_uploader **uploader = (st_uploader **)arg;
    log_info("release uploader\n");
    if (*uploader == NULL) {
        return;
    }
    status = _get_uploader_status(*uploader);
    if (status & __UPLOADER_INTERNAL_STATUS_ALIVE__) {
        _set_uploader_status(*uploader, __UPLOADER_INTERNAL_STATUS_OFF__);
        pthread_join((*uploader)->upload_data_threadid, &ret);
        if (ret == NULL) {
            upload_index_files(*uploader);
        } else {
            _set_uploader_status(*uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
            log_error("something goes wrong %d\n", (int)ret);
        }
    }
    // release upload parameters
    free_upload_parameters(&((*uploader)->snapshot_upload_param));
    free_upload_parameters(&((*uploader)->video_upload_param));
    free_upload_parameters(&((*uploader)->snapshot_index_upload_param));
    free_upload_parameters(&((*uploader)->video_index_upload_param));
    if ((*uploader)->keyhash != NULL) {
        free((*uploader)->keyhash);
        (*uploader)->keyhash = NULL;
        (*uploader)->keyhash_size = 0;
    }
    release_upload_cycle_queue(&((*uploader)->cq));
    pthread_mutex_destroy(&((*uploader)->lock));
    free(*uploader);
    *uploader = NULL;
}

uint8_t get_uploader_status(void *arg) {
    st_uploader *uploader = (st_uploader *)arg;
    uint8_t status = _get_uploader_status(uploader);
    if ((status & __UPLOADER_INTERNAL_STATUS_ERROR__) != 0) {
        return UPLOADER_STATUS_ERROR;
    }
    if ((status & __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__) != 0 && (status & __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__) != 0) {
        return UPLOADER_STATUS_DONE;
    }
    return UPLOADER_STATUS_ALIVE;
}

void process_frame(void *arg, void *arg2) {
    st_uploader *uploader = (st_uploader *)arg;
    st_frame_info *frame = (st_frame_info *)arg2;
    uint8_t *concat_frame = NULL;
    uint8_t status = _get_uploader_status(uploader);
    st_frame_header frame_header;
    if (frame == NULL) {
        log_error("early quit\n");
        // early quit
        if (uploader->video_cache_size > 0) {
            // flush remaining video frames
            if (upload_video(uploader) != 0) {
                return;
            }
        }
        _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__);
        if ((status & __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__) == 0 && (status & __UPLOADER_INTERNAL_STATUS_ERROR__) == 0) {
            if (upload_snapshot_index(uploader) != 0) {
                _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
                return;
            }
        }
        _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__);
        return;
    }
    if (frame->buffer == NULL || frame->size == 0) {
        return; // ignore empty frame
    }
    if (
        (status & __UPLOADER_INTERNAL_STATUS_ALIVE__) == 0 ||
        (status & __UPLOADER_INTERNAL_STATUS_ERROR__) != 0 ||
        (status & __UPLOADER_INTERNAL_STATUS_OFF__) != 0 ||
        ((status & __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__) != 0 && (status & __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__) != 0)
    ) {
        return;
    }
    frame_header.headersize = sizeof(frame_header);
    frame_header.size = frame->size + frame_header.headersize;
    frame_header.channel = frame->channel;
    frame_header.codecid = frame->codecid;
    frame_header.frametype = frame->frametype;
    frame_header.pts = frame->pts;
    frame_header.version = frame->version;
    frame_header.encryptID = frame->encryptID;
    memcpy(frame_header.hash, frame->hash, IOECR_HASH_LENGTH);
    if (frame->frametype == 1) { // replaced with is_iframe
        if (uploader->keyhash == NULL || uploader->keyhash_size == 0) {
            uploader->keyhash = (uint8_t *)strndup((const char *)frame->hash, IOECR_HASH_LENGTH);// replace with hash_size
            if (uploader->keyhash == NULL) {
                _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
                return;
            }
            uploader->keyhash_size = IOECR_HASH_LENGTH;
        }
        if (uploader->num_of_snapshots_to_capture != 0 && uploader->snapshot_count < uploader->num_of_snapshots_to_capture) {
            if ((concat_frame = malloc(frame_header.size)) == NULL) {
                _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
                return;
            }
            memcpy(concat_frame, &frame_header, frame_header.headersize);
            memcpy(concat_frame + frame_header.headersize, frame->buffer, frame->size);
            if (upload_snapshot(uploader, concat_frame, frame_header.size) != 0) {
                free(concat_frame);
                concat_frame = NULL;
                return;
            }
            free(concat_frame);
            concat_frame = NULL;
            if (uploader->num_of_snapshots_to_capture != 0 && uploader->snapshot_count >= uploader->num_of_snapshots_to_capture) {
                if (upload_snapshot_index(uploader) != 0) {
                    log_error("failed to upload snapshot index file");
                    _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
                    return;
                }
                _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_SNAPSHOT_DONE__);
            }
        }
    }
    if (uploader->keyhash == NULL || uploader->start_pts > frame->pts) {
        // skip frames until iframe
        return;
    }
    if ((status & __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__) != 0) {
        return;
    }
    if (uploader->start_pts == 0) {
        uploader->start_pts = frame->pts;
    }
    if (frame_header.size > MAX_VIDEO_CACHE_SIZE) {
        log_error("frame size %d is larger than max video cache size %d", frame_header.size, MAX_VIDEO_CACHE_SIZE);
        _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_ERROR__);
        return;
    }
    if (uploader->video_cache_size + frame_header.size > MAX_VIDEO_CACHE_SIZE) {
        // flush existing video data
        if (upload_video(uploader) != 0) {
            return;
        }
    }
    memcpy(uploader->video_cache + uploader->video_cache_size, &frame_header, frame_header.headersize);
    uploader->video_cache_size += frame_header.headersize;
    memcpy(uploader->video_cache + uploader->video_cache_size, frame->buffer, frame->size);
    uploader->video_cache_size += frame->size;
    uploader->msecond_recorded = frame->pts - uploader->start_pts;
    if (uploader->msecond_recorded >= uploader->msecond_to_record) {
        if (upload_video(uploader) != 0) {
            return;
        }
        _set_uploader_status(uploader, __UPLOADER_INTERNAL_STATUS_VIDEO_DONE__);
    }
}
