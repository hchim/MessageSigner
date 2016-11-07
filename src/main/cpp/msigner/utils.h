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
#endif //MESSAGESIGNER_UTILS_H
