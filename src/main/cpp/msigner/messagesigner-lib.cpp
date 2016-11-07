#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <aes.h>
#include <sha.h>

#include "package_utils.h"
#include "jni_log.h"
#include "apikey_decoder.h"

#define TAG "MessageSigner"

//uint8_t c2i(char c)
//{
//    if (c >= '0' && c <= '9') return      c - '0';
//    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
//    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
//    return -1;
//}
//
//uint8_t* hex2bin(const char* in)
//{
//    size_t len = strlen(in);
//    uint8_t* out = (uint8_t *) malloc((len / 2) * sizeof(uint8_t));
//    int i;
//    for (i = 0; i < len; i += 2)
//    {
//        out[i / 2] = c2i(in[i]) * 16 + c2i(in[i + 1]);
//    }
//    return out;
//}
//
//char* bin2hex(const uint8_t* data, size_t len)
//{
//    char* buffer = (char*)calloc(len * 2, sizeof(char));
//    int i;
//    for (i = 0; i < len; ++i)
//    {
//        sprintf(buffer + (i * 2), "%02X", data[i]);
//        // printf("%d:%02X\n", i, data[i]);
//    }
//    return buffer;
//}
//
//void aesTest()
//{
//    const char* text = "6BC1BEE22E409F96E93D7E117393172A";
//    const uint8_t* data = hex2bin(text);
//    const char* password = "2B7E151628AED2A6ABF7158809CF4F3C";
//    const uint8_t* key = hex2bin(password);
//
//    unsigned char enc_out[AES_BLOCK_SIZE];
//    unsigned char dec_out[AES_BLOCK_SIZE];
//
//    // aes encrypt
//    AES_KEY aes_enc_ctx;
//    AES_set_encrypt_key(key, 128, &aes_enc_ctx);
//    AES_encrypt(data, enc_out, &aes_enc_ctx);
//
//    // aes decrypt
//    AES_KEY aes_dec_ctx;
//    AES_set_decrypt_key(key, 128, &aes_dec_ctx);
//    AES_decrypt(enc_out, dec_out, &aes_dec_ctx);
//}

// used to store apikey verification status
int apikey_verified = -1;

////////////////////////////////////////////////////////////////////////////
// Native Methods of the MessageSigner class.
////////////////////////////////////////////////////////////////////////////

extern "C"
void
Java_im_hch_mapikey_messagesigner_MessageSigner_nativeInit (
        JNIEnv* env,
        jobject thiz) {
    if (apikey_verified == -1) {
        apikey_verified = verify_api_key();
    }
}

extern "C"
jstring
Java_im_hch_mapikey_messagesigner_MessageSigner_nativeSignMessage (
        JNIEnv* env,
        jobject thiz,
        jstring message) {
    if (apikey_verified != 1) {
        LOGE(TAG, "Failed to sign message.");
        return NULL;
    }

    //TODO sign message

    return env->NewStringUTF("Test string");
}