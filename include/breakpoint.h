#pragma once

#include "config.h"
#include "types.h"

enum breakpoint_state {
    BRK_UNINIT,
    BRK_ENABLED,
    BRK_DISABLED,
};

typedef struct breakpoint_t {
    size_t address;
    u64 original_data;
    enum breakpoint_state state;
} breakpoint_t;

i32 breakpoint_new(config_t* cfg, size_t const address);
breakpoint_t const* breakpoint_get(vec_t const* breakpoints, size_t const address);
i32 breakpoint_setup(config_t* cfg);
i32 breakpoint_enable_id(config_t* cfg, size_t const id);
i32 breakpoint_disable_id(config_t* cfg, size_t const id);
void breakpoint_list(config_t const* cfg);
i32 breakpoint_step(config_t* cfg);
i32 breakpoint_remove_id(config_t* cfg, size_t const id);
i32 breakpoint_remove_address(config_t* cfg, size_t const address);
