#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *parse_token(const char *input, size_t size);

int main(void)
{
    char line[32];
    if (fgets(line, sizeof(line), stdin) == NULL)
        return 2;

    size_t size = strcspn(line, "\n");
    char *token = parse_token(line, size);
    if (token == NULL)
        return 2;

    puts(token);
    free(token);
    return 0;
}
