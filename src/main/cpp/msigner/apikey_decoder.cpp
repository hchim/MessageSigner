#include <string.h>
#include <base64.h>
#include <json.h>
#include <stdio.h>
#include <iostream>

#include "package_utils.h"
#include "apikey_decoder.h"
#include "jni_log.h"

#include "pkcs7.h"

#define TAG "APIKeyDecoder"

using namespace std;

/*
 * Generate the sha256 signature of the public key certificate that the apk file was signed with.
 */
int generate_public_key_signature(char* apk_path, char* cert_file, char* signature) {
    // read the public key certificate
    uint8_t * cert_buff;
    int len = read_file_from_apk(apk_path, cert_file, &cert_buff);
    if (len < 0) {
        if (cert_buff != NULL) {
            free(cert_buff);
        }
        return 0;
    }
    LOGD(TAG, "len %d\n", len);
    pkcs7 cert;
    cert.set_content(cert_buff, len);

    char * sig = cert.get_SHA256();
    if (sig != NULL) {
        strncpy(signature, sig, strlen(sig));
    }

    free(cert_buff);
    return 1;
}

int read_api_key(char* apk_path, APIKey* apiKey) {
    uint8_t * key_buff;
    size_t len = read_file_from_apk(apk_path, "assets/apikey", &key_buff);

    if (len < 0) {
        if (key_buff != NULL) {
            free(key_buff);
        }
        return 0;
    }

    // decode apikey
    if (!decode_api_key((char*) key_buff, apiKey)) {
        free(key_buff);
        return 0;
    }
    free(key_buff);

    return 1;
}

int verify_api_key() {
    char package_name[256] = {0};
    char apk_path[1024] = {0};
    char cert_file[256] = {0};
    char signature[256] = {0};
    APIKey apiKey_obj;

    if (!get_package_name(package_name) ||
        !get_apk_file_path(package_name, apk_path) ||
        !get_certificate_file(apk_path, cert_file) ||
        !generate_public_key_signature(apk_path, cert_file, signature) ||
        !read_api_key(apk_path, &apiKey_obj)) {
        return 0;
    }

    LOGD(TAG, "sig: %s signature: %s\n", signature, apiKey_obj.signature);
    if (strcmp(apiKey_obj.package_name, package_name) != 0
        || strcmp(apiKey_obj.signature, signature) != 0) {
        return 0;
    }
    //TODO verify apikey signature

    return 1;
}

const char* read_string(json_object * jobj, const char* key) {
    json_object * obj;
    if (!json_object_object_get_ex(jobj, key, &obj)) {
        return NULL;
    }

    const char* str = json_object_get_string(obj);
    return str;
}

int decode_api_key(const char * str, APIKey* apiKey) {
    char* p = strstr(str, ".");
    if (p == NULL) {
        LOGD(TAG, "Failed to decode api key: %s\n", str);
        return 0;
    }
    //split the string
    *p = 0;
    p += 1;

    uint8_t json[2048];
    uint8_t sig[2048];
    size_t len, len2;
    if (!EVP_DecodeBase64(json, &len, sizeof(json), (const uint8_t*) str, strlen(str)) ||
        !EVP_DecodeBase64(sig, &len2, sizeof(sig), (const uint8_t*) p, strlen(p))) {
        LOGD(TAG, "Failed to decode base64 str: %s %s\n", str, sig);
        return 0;
    }

    json_object * jobj = json_tokener_parse((char*) json);
    if (jobj == NULL) {
        return 0;
    }

    const char* str_obj;
    str_obj = read_string(jobj, "version");
    if (str_obj != NULL) {
        strncpy(apiKey->version, str_obj, strlen(str_obj) + 1);
    }

    str_obj = read_string(jobj, "algorithm");
    if (str_obj != NULL) {
        strncpy(apiKey->algorithm, str_obj, strlen(str_obj) + 1);
    }

    str_obj = read_string(jobj, "packageName");
    if (str_obj != NULL) {
        strncpy(apiKey->package_name, str_obj, strlen(str_obj) + 1);
    }

    str_obj = read_string(jobj, "signature");
    if (str_obj != NULL) {
        strncpy(apiKey->signature, str_obj, strlen(str_obj) + 1);
    }

    strncpy(apiKey->apikey_signature, p, strlen(p));

    return 1;
}