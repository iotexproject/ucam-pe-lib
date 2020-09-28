#ifndef _IOECR_UPLOAD_DATA_H_
#define _IOECR_UPLOAD_DATA_H_

#include <stdint.h>

#ifndef CA_CERTIF_FILE
#define CA_CERTIF_FILE "/tmp/cacert.pem"
#endif

#define UPLOAD_PARAM_SNAPSHOT_COUNT "snapshotcount"
#define UPLOAD_PARAM_VIDEO_DURATION "videoduration"
#define UPLOAD_PARAM_KEY "key"

typedef struct {
    char *url;
    uint32_t size;
    char **names;
    char **values;
} st_upload_parameter;

typedef struct {
    st_upload_parameter *param;
    char *suffix;
    uint32_t suffix_len;
    uint8_t *data;
    uint32_t size;
} st_upload_data;

st_upload_data *new_upload_data(st_upload_parameter *param, const char *suffix, uint32_t suffix_len, uint8_t *data, uint32_t size);

void free_upload_data(st_upload_data *ud);

int post_data(st_upload_data *ud);

int is_parameter(const char *name, const char *param);

#endif