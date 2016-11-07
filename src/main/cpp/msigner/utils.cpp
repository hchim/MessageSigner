#include <sha.h>
#include <md5.h>
#include <stdio.h>

#include "utils.h"

void SHA256_digest(const uint8_t * data, int len, char signature[65]) {
    if (data == NULL) {
        return;
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(signature + (i * 2), "%02x", hash[i]);
    }

    signature[64] = '\0';
}

void MD5_digest(const uint8_t * data, int len, char digest[33]) {
    if (data == NULL) {
        return;
    }

    uint8_t hash[MD5_DIGEST_LENGTH];
    MD5(data, len, hash);

    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(digest + (i * 2), "%02x", hash[i]);
    }

    digest[32] = '\0';
}