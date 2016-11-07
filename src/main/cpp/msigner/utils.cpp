#include <sha.h>
#include <stdio.h>

#include "utils.h"

void SHA256_digest(const char * data, int len, char signature[SHA256_CBLOCK + 1]) {
    if (data == NULL) {
        return;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(signature + (i * 2), "%02x", hash[i]);
    }

    signature[SHA256_CBLOCK] = 0;
}