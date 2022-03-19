#pragma once

#include "../ext/vec.h"
#include "types.h"

enum state_t {
    STATE_UNINIT,
    STATE_INIT,
    STATE_RUNNING,
};

typedef struct config_t {
    char* target;
    pid_t pid;
    pid_t inferior_pid;
    size_t inferior_start;
    vec_t* breakpoints;
    enum state_t state;
} config_t;

config_t* config_new(char* target);
void config_drop(config_t* self);
void config_load(config_t* self, char const* target);
char const* config_target(config_t const* self);
void config_print(config_t const* self);
