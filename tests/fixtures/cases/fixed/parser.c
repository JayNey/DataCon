#include <stddef.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_TOKEN = 4 };

char *parse_token(const char *input, size_t size)
{
    if (size > MAX_TOKEN)
        return NULL;

    char *token = malloc(MAX_TOKEN + 1);
    if (token == NULL)
        return NULL;

    memcpy(token, input, size);
    token[size] = '\0';
    return token;
}
