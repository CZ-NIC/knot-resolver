#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "lib/defines.h"
#include "lib/utils.h"

/*
 * Macros.
 */
#define strlen_safe(x) ((x) ? strlen(x) : 0)

/*
 * Cleanup callbacks.
 */
void _cleanup_free(char **p)
{
    free(*p);
}

void _cleanup_close(int *p)
{
    if (*p > 0) close(*p);
}

char* kr_strcatdup(unsigned n, ...)
{
    /* Calculate total length */
    size_t total_len = 0;
    va_list vl;
    va_start(vl, n);
    for (unsigned i = 0; i < n; ++i) {
        char *item = va_arg(vl, char *);
        total_len += strlen_safe(item);
    }
    va_end(vl);

    /* Allocate result and fill */
    char *result = NULL;
    if (total_len > 0) {
        result = malloc(total_len + 1);
    }
    if (result) {
        char *stream = result;
        va_start(vl, n);
        for (unsigned i = 0; i < n; ++i) {
            char *item = va_arg(vl, char *);
            if (item) {
                size_t len = strlen(item);
                memcpy(stream, item, len + 1);
                stream += len;
            }
        }
        va_end(vl);
    }

    return result;
}