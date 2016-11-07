#include <string.h>
#include <stdio.h>

#include "string_extra.h"

int ends_with(const char* str, const char* end_str) {
    if (str == NULL || end_str == NULL) {
        return 0;
    }

    size_t str_size = strlen(str);
    size_t end_size = strlen(end_str);

    if (end_size > str_size) {
        return 0;
    }

    char* p = strstr(str, end_str);
    if (p != NULL && strlen(p) == end_size) {
        return 1;
    }

    return 0;
}