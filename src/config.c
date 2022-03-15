#include <string.h>

#include "../include/config.h"
#include "../include/utils.h"

typedef struct config_s {
    char* target;
    char** args;
    size_t nb_args;
} config_t;

config_t *config_new(char* target, char** args, size_t nb_args)
{
    config_t* cfg = malloc(sizeof(config_t));
    UD_assert(cfg, "config allocation failed");
    cfg->target = target;
    cfg->args = args;
    cfg->nb_args = nb_args;
    return cfg;
}

void config_drop(config_t *self)
{
    UD_assert(self, "invalid parameter (null pointer)");
    if (self->args) {
        for (size_t i = 0; i < self->nb_args + 1; i++) {
            free(self->args[i]);
        }
    }
    free(self);
}

void config_set_target(config_t* self, char const* target)
{
    UD_assert(self && target, "invalid parameter (null pointer)");
    self->target = malloc(strlen(target) + 1);
    UD_assert(self->target, "config's target allocation failed");
    self->target = strcpy(self->target, target);
    UD_assert(self->target, "config's target string copy failed");
    printf("%s%sinfo:%s target set to `%s`.\n", BOLD, MAGENTA, NORMAL, self->target);
}

void config_set_args(config_t* self, char const* args)
{
    UD_assert(self && args, "invalid parameter (null pointer)");
    self->args = strsplit(args, " ");
    self->nb_args = substr_cnt(args, " ");
    printf("%s%sinfo:%s arguments set to [", BOLD, MAGENTA, NORMAL);
    UD_assert(self && args, "invalid parameter (null pointer)");
    for (size_t i = 1; i < self->nb_args + 1; i++) {
        printf(" `%s`", self->args[i]);
    }
    printf(" ].\n");
}

char const* config_target(config_t const* self)
{
    UD_assert(self, "invalid parameter (null pointer)");
    if (!self->target) {
        return NULL;
    }
    char* target = malloc(strlen(self->target) * sizeof(char));
    UD_assert(target, "config target allocation failed");
    target = strcpy(target, self->target);
    UD_assert(target, "config target copy failed");
    return target;
}

char* const* config_args(config_t const* self)
{
    UD_assert(self, "invalid parameter (null pointer)");
    if (!self->args) {
        return NULL;
    }
    char** args = malloc(self->nb_args * sizeof(char*));
    UD_assert(args, "config arguments list allocation failed");
    for (size_t i = 0; i < self->nb_args + 1; i++) {
        args[i] = malloc(strlen(self->args[i]) + 1);
        UD_assert(args, "config argument allocation failed");
        args[i] = strcpy(args[i], self->args[i]); 
        UD_assert(args, "config arguments copy failed");
    }
    return args;
}

void config_print(config_t const* self)
{
    UD_assert(self, "invalid parameter (null pointer)");
    printf("Current executable is set to `%s` with arguments: [", self->target);
    for (size_t i = 1; i < self->nb_args + 1; i++) {
        printf(" `%s`", self->args[i]);
    }
    printf(" ].\n");
}
