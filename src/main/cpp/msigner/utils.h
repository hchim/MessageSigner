#ifndef MESSAGESIGNER_UTILS_H
#define MESSAGESIGNER_UTILS_H

/*
 * Generate the SHA256 digest.
 */
void SHA256_digest(const uint8_t * data, int len, char digest[65]);

/*
 * Generate the MD5 digest.
 */
void MD5_digest(const uint8_t * data, int len, char digest[33]);

/*
unsigned char*  text;                pointer to data stream
int             text_len;            length of data stream
unsigned char*  key;                 pointer to authentication key
int             key_len;             length of authentication key
unsigned char*  digest;              caller digest to be filled in
*/
void hmac_md5(const uint8_t *text, int text_len,
              const uint8_t *key, int key_len,
              char *digest);
#endif //MESSAGESIGNER_UTILS_H
