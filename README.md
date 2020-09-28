# UCam Privacy Enhancement Lib

This is UCam Privacy Enhancement (PE) library that is invoked by the main firmware (which is unfortunately close source) to :
* Encrypt snapshot provided by the main firmware.
* Encrypt video stream frame by frame.
* Upload encrypted video frame file.
* Upload encrypted snapshot to AWS S3 and Filecoin (WIP).
* Handle OTA update via IPFS

## Layout
This lib depends on `libcurl` and `libmbedtls`, primarily contains `ioecr` and `emulator`, where the former implements the privacy-enhancement features while the latter is for emulation and testing purposes. For `ioecr`, the most important files are:
```
 |-- libioecr.h: API interface
 |-- libioecr.a: static library of the API implementation
```

## How to Use
### 1. Register callback

The SDK needs couple of callback from firmware to make it work properly. So first firmware needs to make 2 calls
```
  int ioecr_initialize_recorder(
    cb_get_credential get_credential,
    cb_release_credential release_credential);
```

Correspondingly, they can be release with `void ioecr_release_recorder();`

this will register these callbacks for use by video upload component `int ioecr_initialize_encryptor();`

this loads the key into the encryption component. The corresponding release function is `void ioecr_release_encryptor();``

### 2. Check encryption key

To check if a key matches current key, firmware needs to call `int ioecr_check_encryption_key(const uint8_t* hash, int length, uint32_t *nonce);`

hash is 20-byte buffer containing the hmac-sha1() of current key, length must be 20.

### 3. Set encryption key
To set encryption key, firmware needs to call

`int ioecr_set_encryption_key(uint32_t nonce, const uint8_t* key, int length, const uint8_t *curr_key_hash, int hash_length);``

key is 16-byte buffer containing new key, length must be 16, `curr_key_hash` is same as input to `ioecr_check_encryption_key`, hash_length must be 20.

Upon success, the provided key is written into the file "/rom/key" on the camera file system.

If `ioecr_set_encryption_key()` is not called, or is called with key == NULL, then encryption is disabled.
To enable encryption, `ioecr_set_encryption_key()` must be called with a valid 16-byte key.

### 4. Encrypt a frame

To encrypt a frame, firmware needs to call
`int ioecr_encrypt(uint8_t *buffer, uint32_t buffer_size, uint8_t *nonce_counter, uint8_t *key_hash);`

return value will be 0 if encryption is disabled, > 0 is the encryption algorithm ID (currently 1), firmware needs to write this ID (or 0 meaning disabled) into frame header. A value < 0 indicates error code from encryption library.

`nonce_counter` is 16-byte buffer, and contains the nonce and counter needed to decrypt the frame.
key_hash is 4-byte buffer, and contains the first 4-bytes of hmac-sha1() of current encryption key

### 5. Record a video clip (and/or snapshot)

To respond to an alarm event, firmware needs to call
`int ioecr_start_recording(pthread_t* pthreadid);``

If user has video privilege, this will upload to S3 storage one or more files. Each video file contains multiple video frames, where each video frame consists of a `st_frame_header` (28-bytes), followed by the actual frame data. The library keeps calling firmware's callback `cb_get_frame(&frameinfo)`, fill the header and copy actual frame data according to `frameinfo`, until all frames up to the requested time have been processed and uploaded.

If user has snapshot privilege, this will upload to S3 storage 'snapshot_count' snapshot files. Each file contains a size_t follow with the frame data.

# Contribute

Want to contribute to the this firmware project? Follow [this link](CONTRIBUTIONS.md) to find out how.

# License
Unless stated elsewhere, file headers or otherwise, all files herein are licensed under an LGPLv3 license. For more information, please read the LICENSE file.

This license allows businesses to confidently build firmware and make devices without risk to their intellectual property, while at the same time helping the community benefit from non-proprietary contributions to the shared System Firmware.

# Connect

Having problems or have awesome suggestions? Connect with us [here](support@iotex.io).
