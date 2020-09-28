#include <assert.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "upload_data.h"

int is_parameter(const char *name, const char *param) {
  assert(name != NULL);
  assert(param != NULL);

  uint32_t name_len = strlen(name);
  uint32_t param_len = strlen(param);

  return name_len == param_len && strncmp(name, param, name_len) == 0;
}

void free_upload_data(st_upload_data *ud) {
    if (ud == NULL) {
        return;
    }
    if (ud->data != NULL) {
        free(ud->data);
    }
    if (ud->suffix != NULL) {
        free(ud->suffix);
    }
    free(ud);
}

st_upload_data *new_upload_data(st_upload_parameter *param, const char *suffix, uint32_t suffix_len, uint8_t *data, uint32_t size) {
    st_upload_data *ud = calloc(1, sizeof(st_upload_data));
    if (ud == NULL) {
        return NULL;
    }
    ud->param = param;
    ud->data = NULL;
    ud->suffix = NULL;
    if ((ud->data = calloc(1, size)) == NULL) {
        free_upload_data(ud);
        return NULL;
    }
    ud->size = size;
    memcpy(ud->data, data, size);
    if ((ud->suffix = calloc(1, suffix_len)) == NULL) {
        free_upload_data(ud);
        return NULL;
    }
    ud->suffix_len = suffix_len;
    memcpy(ud->suffix, suffix, suffix_len);

    return ud;
}

int post_data(st_upload_data *ud) {
    CURLcode ret;
    CURL *hnd;
    curl_mime *mime1;
    curl_mimepart *part1;
    uint32_t value_len;
    long response_code;
    char *values;
    int i;
    if (ud == NULL) {
        return 0;
    }

    // assume that the certificate file has been created
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, ud->param->url);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
    //curl_easy_setopt(hnd, CURLOPT_CAINFO, CA_CERTIF_FILE);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    mime1 = curl_mime_init(hnd);

    for (i = 0; i < ud->param->size; i++) {
        if (is_parameter(ud->param->names[i], UPLOAD_PARAM_SNAPSHOT_COUNT)) {
            continue;
        }
        if (is_parameter(ud->param->names[i], UPLOAD_PARAM_VIDEO_DURATION)) {
            continue;
        }
        part1 = curl_mime_addpart(mime1);
        if (is_parameter(ud->param->names[i], UPLOAD_PARAM_KEY)) {
            value_len = strlen(ud->param->values[i]);
            values = malloc(value_len + ud->suffix_len + 1);
            memcpy(values, ud->param->values[i], value_len);
            memcpy(values + value_len, ud->suffix, ud->suffix_len);
            values[value_len + ud->suffix_len] = 0;
            curl_mime_data(part1, values, value_len + ud->suffix_len);
            log_info("uploading file %s", values);
            free(values);
        } else {
            curl_mime_data(part1, ud->param->values[i], strlen(ud->param->values[i]));
        }
        curl_mime_name(part1, ud->param->names[i]);
    }
    part1 = curl_mime_addpart(mime1);
    if (ud->size == 0 || ud->data == NULL) {
        curl_mime_data(part1, "", 0);
    } else {
        curl_mime_data(part1, (const char *)ud->data, ud->size);
    }
    curl_mime_name(part1, "file");
    curl_easy_setopt(hnd, CURLOPT_MIMEPOST, mime1);
    curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    ret = curl_easy_perform(hnd);
    if (ret == 0) {
        curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code >= 300) {
            log_error("failed to upload data %d\n", response_code);
            ret = 1;
        }
    }
    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_mime_free(mime1);
    mime1 = NULL;

    return ret;
}
