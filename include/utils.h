#pragma once

#include <stdio.h>
#include <stdlib.h>

#include "consts.h"
#include "types.h"

#include <string.h>

#define UDB_assert(expr, msg)                                                        \
    do {                                                                            \
        if (!(expr)) {                                                              \
            fprintf(stderr, "%s%sassertion failed:%s %s:%d in %s\n  { `%s` }: %s\n",\
                    BOLD, RED, NORMAL, __FILE__, __LINE__, __func__,                \
                    #expr, msg);                                                    \
            exit(EXIT_FAILURE);                                                     \
        }                                                                           \
    } while (0)

#define UDB_debug(value, fmt)                                                        \
    do {                                                                            \
        if (!strcmp(fmt, "str")) {                                                  \
            fprintf(stderr, "%s%sdebug%s: %s:%d\n  --> identifier `%s` = '%s'\n",   \
                    BOLD, CYAN, NORMAL, __FILE__, __LINE__,                         \
                    #value, value);                                                 \
        } else if (!strcmp(fmt, "int")) {                                           \
            fprintf(stderr, "%s%sdebug%s: %s:%d\n    --> identifier `%s` = %d\n",   \
                    BOLD, CYAN, NORMAL, __FILE__, __LINE__,                         \
                    #value, value);                                                 \
        }                                                                           \
    } while (0)

void help();
char* strstrip(char* str);
char** strsplit(char** args, char const* str, char const* delimeter);
size_t substr_cnt(char const* str, char const* substr);
size_t parse_value(char const* str);
