#ifndef MESSAGESIGNER_UTILS_H
#define MESSAGESIGNER_UTILS_H

#include <sha.h>

/*
 * Generate the SHA256 signature.
 */
void SHA256_digest(const char * data, int len, char signature[SHA256_CBLOCK + 1]);

#endif //MESSAGESIGNER_UTILS_H
