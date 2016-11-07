#ifndef MESSAGESIGNER_APIKEY_DECODER_H
#define MESSAGESIGNER_APIKEY_DECODER_H

typedef struct api_key {
    char version[4];
    char algorithm[16];
    char package_name[256];
    char signature[128];
    char apikey_signature[512];
} APIKey;

/*
 * Decode the json string to an api key obj.
 */
int decode_api_key(const char* json, APIKey* apiKey);

/*
 * Verify API key.
 */
int verify_api_key(char * key);

#endif //MESSAGESIGNER_APIKEY_DECODER_H
