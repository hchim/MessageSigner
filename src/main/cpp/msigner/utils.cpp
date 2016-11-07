#include <unistd.h>
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

void hmac_md5(const uint8_t *text, int text_len,
              const uint8_t *key, int key_len,
              char *digest)
{
    uint8_t hash[MD5_DIGEST_LENGTH];
    MD5_CTX context;
    unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
    unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
    unsigned char tk[16];
    int i;
    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if (key_len > 64) {

        MD5_CTX      tctx;

        MD5_Init(&tctx);
        MD5_Update(&tctx, key, key_len);
        MD5_Final(tk, &tctx);

        key = tk;
        key_len = 16;
    }

    /*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times

     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* start out by storing key in pads */
    memset( k_ipad, 0, sizeof(k_ipad));
    memset( k_opad, 0, sizeof(k_opad));
    memcpy( k_ipad, key, key_len);
    memcpy( k_opad, key, key_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    /*
     * perform inner MD5
     */
    MD5_Init(&context);                   /* init context for 1st
                                              * pass */
    MD5_Update(&context, k_ipad, 64);      /* start with inner pad */
    MD5_Update(&context, text, text_len); /* then text of datagram */
    MD5_Final(hash, &context);          /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    MD5_Init(&context);                   /* init context for 2nd
                                              * pass */
    MD5_Update(&context, k_opad, 64);     /* start with outer pad */
    MD5_Update(&context, hash, 16);     /* then results of 1st
                                              * hash */
    MD5_Final(hash, &context);          /* finish up 2nd pass */

    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(digest + (i * 2), "%02x", hash[i]);
    }

    digest[32] = '\0';
}