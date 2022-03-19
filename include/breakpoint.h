#pragma once

#include "config.h"
#include "types.h"

typedef struct breakpoint_t {
    size_t address;
    u64 original_data;
    bool is_enabled;
} breakpoint_t;

i32 breakpoint_new(config_t* cfg, size_t const address);
i32 breakpoint_remove_address(config_t* cfg, size_t const address);
i32 breakpoint_remove_id(config_t* cfg, size_t const id);
i32 breakpoint_step(config_t* cfg);
breakpoint_t* breakpoint_peek(vec_t* breakpoints, size_t const address);
