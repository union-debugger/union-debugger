#pragma once

#include "types.h"

typedef struct config_s {
    char* target;
    pid_t pid;
    pid_t inferior_pid;
    size_t inferior_start;
} config_t;

config_t* config_new(char* target);
void config_drop(config_t* self);
void config_load(config_t* self, char const* target);
char const* config_target(config_t const* self);
void config_print(config_t const* self);
