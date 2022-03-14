#pragma once

#include "types.h"

typedef struct config_s config_t;

config_t* config_new(char* target, char** args, size_t nb_args);
void config_drop(config_t *self);
void config_set_target(config_t *self, char const* target);
void config_set_args(config_t *self, char const* args);
char const* config_target(config_t const* self);
char* const* config_args(config_t const* self);
void config_print(config_t const* self);
