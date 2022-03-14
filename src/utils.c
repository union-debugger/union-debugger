#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../include/consts.h"
#include "../include/utils.h"

void help()
{
    fprintf(stderr, "udb v0.1.0 — Union's Debugging Software\n");
    fprintf(stderr, "\n%sUSAGE:%s\n    ./udb [OPTIONS] [FLAGS]\n", BOLD, NORMAL);
    fprintf(stderr, "\n%sOPTIONS:%s\n", BOLD, NORMAL);
    fprintf(stderr, "    --path,     -p <PATH>\tPath to target program.\n");
    fprintf(stderr, "    --args,     -a <ARGS>\tArguments of target program.\n");
    fprintf(stderr, "\n%sFLAGS:%s\n", BOLD, NORMAL);
    fprintf(stderr, "    --help,     -h\t\tPrints this help.\n");
    fprintf(stderr, "    --version,  -v\t\tPrints current version.\n");
}

bool exists(char const* path)
{
    UD_assert(path, "invalid parameter (null pointer)");
    return access(path, F_OK) ? true : false;
}

char* strstrip(char* str)
{
    UD_assert(str, "invalid parameter (null pointer)");
    char* strip = malloc(strlen(str) + 1);
    UD_assert(strip, "stripped string allocation failed");
    if (strip) {
        char* ptr = strip;
        while (*str != '\0') {
            if (*str != '\t' && *str != '\n') {
                *ptr++ = *str++;
            } else {
                ++str;
            }
        }
        *ptr = '\0';
    }
    return strip;
}

char** strsplit(char const* str, char const* delimeter)
{
    UD_assert(str && delimeter, "invalid parameter (null pointer)");
    char** tokens = NULL;
    char* cpy = malloc(strlen(str) + 1);
    UD_assert(cpy, "string allocation failed");
    cpy = strcpy(cpy, str); 
    UD_assert(cpy, "string copy failed");

    char* tmp = strtok(cpy, delimeter);
    UD_assert(tmp, "delimeter not found in string");
    size_t nb_delims = 0;
    tokens = realloc(tokens, (++nb_delims) * sizeof(char*));
    UD_assert(tokens, "token's reallocation failed");
    tokens[0] = "easter egg bro";
    while (tmp) {
        tokens = realloc(tokens, (++nb_delims) * sizeof(char*));
        UD_assert(tokens, "token's reallocation failed");
        tokens[nb_delims - 1] = tmp;
        tmp = strtok(NULL, delimeter);
    }

    tokens = realloc(tokens, (nb_delims + 1) * sizeof(char*));
    UD_assert(tokens, "token's reallocation failed");
    tokens[nb_delims] = NULL;

    return tokens;
}

size_t substr_cnt(char const* str, char const* substr)
{
    UD_assert(str && substr, "invalid parameter (null pointer)");
    size_t count = 1;
    char const* tmp = str;
    while ((tmp = strstr(tmp, substr))) {
        count += 1;
        tmp++;
    }
    return count;
}
