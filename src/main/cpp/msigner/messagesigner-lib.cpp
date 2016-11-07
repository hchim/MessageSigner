#include <jni.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "jni_log.h"
#include "apikey_decoder.h"

#define TAG "MessageSigner"

////////////////////////////////////////////////////////////////////////////
// Native Methods of the MessageSigner class.
////////////////////////////////////////////////////////////////////////////
// used to store apikey verification status
int apikey_verified = -1;
char key[1024] = {0};
int key_len = 0;

extern "C"
void
Java_im_hch_mapikey_messagesigner_MessageSigner_nativeInit (
        JNIEnv* env,
        jobject thiz) {
    if (apikey_verified == -1) {
        apikey_verified = verify_api_key(key);
        if (apikey_verified) {
            key_len = strlen(key);
        }
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

    char signature[33] = {0};
    const char* cmsg = env->GetStringUTFChars(message, 0);
    hmac_md5((const uint8_t *) cmsg, strlen(cmsg), (const uint8_t *) key, key_len, signature);
    return env->NewStringUTF((const char *) signature);
}