#include <stddef.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_TOKEN = 4 };

/*
 * B01 vulnerable revision: the terminator is written one byte past the
 * MAX_TOKEN-byte allocation when the caller passes exactly MAX_TOKEN bytes.
 * The fixed revision allocates MAX_TOKEN + 1.
 */
char *parse_token(const char *input, size_t size)
{
    if (size > MAX_TOKEN)
        return NULL;

    char *token = malloc(MAX_TOKEN);
    if (token == NULL)
        return NULL;

    memcpy(token, input, size);
    token[size] = '\0';
    return token;
}
