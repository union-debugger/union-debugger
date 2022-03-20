#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "../include/consts.h"
#include "../include/utils.h"

void help()
{
    fprintf(stderr, "udb v0.1.0 — Union's Debugger\n");
    fprintf(stderr, "\n%sUSAGE:%s\n    ./udb [OPTIONS] [FLAGS]\n", BOLD, NORMAL);
    fprintf(stderr, "\n%sOPTIONS:%s\n", BOLD, NORMAL);
    fprintf(stderr, "    --path,     -p <PATH>\tPath to target program.\n");
    fprintf(stderr, "\n%sFLAGS:%s\n", BOLD, NORMAL);
    fprintf(stderr, "    --help,     -h\t\tPrints this help.\n");
    fprintf(stderr, "    --version,  -v\t\tPrints current version.\n");
}

char* strstrip(char* str)
{
    UDB_assert(str, "invalid parameter (null pointer)");
    char* strip = malloc(strlen(str) + 1);
    UDB_assert(strip, "stripped string allocation failed");
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

char** strsplit(char** args, char const* str, char const* delimeter)
{
    UDB_assert(str && delimeter, "invalid parameter (null pointer)");
    char* cpy = malloc(strlen(str) + 1);
    UDB_assert(cpy, "string allocation failed");
    cpy = strcpy(cpy, str); 
    UDB_assert(cpy, "string copy failed");

    char* tmp = strtok(cpy, delimeter);
    UDB_assert(tmp, "delimeter not found in string");

    size_t nb_delims = 1;
    while (tmp) {
        args = realloc(args, (++nb_delims) * sizeof(char*));
        UDB_assert(args, "token's reallocation failed");
        args[nb_delims - 1] = tmp;
        tmp = strtok(NULL, delimeter);
    }

    args = realloc(args, (nb_delims + 1) * sizeof(char*));
    UDB_assert(args, "token's reallocation failed");
    args[nb_delims] = NULL;

    return args;
}

size_t substr_cnt(char const* str, char const* substr)
{
    UDB_assert(str && substr, "invalid parameter (null pointer)");
    size_t count = 1;
    char const* tmp = str;
    while ((tmp = strstr(tmp, substr))) {
        count += 1;
        tmp++;
    }
    return count;
}

size_t parse_value(char const* str)
{
    errno = 0;
    char* endptr;
    size_t addr;

    // Check if user used `0x` prefix 
    if (str[0] == '0' && str[1] == 'x') {
        addr = strtoumax(str + 2, &endptr, 16);
    } else {
        addr = strtoumax(str, &endptr, 10);
    }

    if (errno != 0 || endptr == str || *endptr != '\0') {
        return SIZE_MAX;
    }

    return addr;
}
