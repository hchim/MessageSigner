#include <string.h>
#include <base64.h>
#include <json.h>
#include <stdio.h>
#include <iostream>

#include "package_utils.h"
#include "apikey_decoder.h"
#include "jni_log.h"
#include "utils.h"
#include "pkcs7.h"

#define TAG "MessageSigner:apikey_decoder"
// replace with the md5 digest of the apikey signature part
#define APIKEY_SIG_MD5 "354649080795099af4fdd13f010fc867"
#define APK_SIG_SHA256 "B1:72:99:D8:C2:11:AA:71:9E:83:D7:E3:CC:03:05:94:DE:EB:20:67:2F:57:87:E3:CD:C1:8D:D0:69:45:EA:5B"
#define MAGIC_WORD "HCH"

using namespace std;

/*
 * Generate the sha256 signature of the public key certificate that the apk file was signed with.
 */
int generate_public_key_signature(char* apk_path, char* cert_file, char* signature) {
    LOGD(TAG, "apk_path: %s\n", apk_path);
    LOGD(TAG, "cert_file: %s\n", cert_file);
    // read the public key certificate
    uint8_t * cert_buff;
    int len = read_file_from_apk(apk_path, cert_file, &cert_buff);
    if (len < 0) {
        if (cert_buff != NULL) {
            free(cert_buff);
        }
        LOGD(TAG, "Failed to read certificate.\n");
        return 0;
    }

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
    uint8_t * key_buff = NULL;
    int len = read_file_from_apk(apk_path, "assets/apikey", &key_buff);

    if (len <= 0) {
        if (key_buff != NULL) {
            free(key_buff);
        }
        return 0;
    }

    key_buff[len] = '\0';
    // decode apikey
    if (!decode_api_key((char*) key_buff, apiKey)) {
        free(key_buff);
        return 0;
    }
    free(key_buff);

    return 1;
}

int verify_api_key(char * key) {
    char package_name[256] = {0};
    char apk_path[1024] = {0};
    char cert_file[256] = {0};
    char signature[256] = {0};
    APIKey apiKey_obj;

    if (!get_package_name(package_name) || //get the package name of current process
        !get_apk_file_path(package_name, apk_path) || //get the path of the apk file
/*
 * pkcs7.cpp has problem to read .RSA file right now. we hard code signature to this file.
 */
//        !get_certificate_file(apk_path, cert_file) || //get the path of the .RSA file
//        !generate_public_key_signature(apk_path, cert_file, signature) || //generate the sha256 signature of the .RSA file
        !read_api_key(apk_path, &apiKey_obj)) {  //decode apikey
        return 0;
    }

    //TODO use the X.509 certificate to verify the signature
    char MD5[33] = {0};
    int len = strlen(apiKey_obj.apikey_signature);
    MD5_digest((const uint8_t *) apiKey_obj.apikey_signature, len, MD5);

    if (strcmp(apiKey_obj.package_name, package_name) != 0  //compare package name
        /*
         * pkcs7.cpp has problem to read .RSA file right now. we hard code signature to this file.
         */
        || strcmp(apiKey_obj.signature, APK_SIG_SHA256) != 0 //compare the signature of the apk file
        // || strcmp(apiKey_obj.signature, signature) != 0 //compare the signature of the apk file
        || strcmp(MD5, APIKEY_SIG_MD5) != 0) { //compare the signature of the api key
        LOGD(TAG, "sig: %s signature: %s\n", signature, apiKey_obj.signature);
        LOGD(TAG, "pn: %s package_name: %s\n", package_name, apiKey_obj.package_name);
        LOGD(TAG, "apisig: %s apikey_signature: %s\n", APIKEY_SIG_MD5, MD5);
        return 0;
    }

    //prepare key
    len = strlen(package_name);
    strncpy(key, package_name, len);
    strncpy(key + len, MAGIC_WORD, 3);
    len += 3;
    strncpy(key + len, APK_SIG_SHA256, 95);
    len += 95;
    strncpy(key + len, MD5, 32);
    len += 32;
    key[len] = '\0';

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
    if (str == NULL) {
        return 0;
    }

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

    strncpy(apiKey->apikey_signature, p, strlen(p) + 1);

    return 1;
}