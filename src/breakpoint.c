#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "../include/breakpoint.h"
#include "../include/consts.h"
#include "../include/debugger.h"
#include "../include/utils.h"

#define INT3 0xcc

/**
 * Internal functions.
 **/
static
ssize_t breakpoint_search(vec_t const* breakpoints, size_t const address)
{
    ssize_t found = -1;
    for (size_t i = 0; i < breakpoints->len; i++) {
        breakpoint_t const* b = vec_peek(breakpoints, i);
        if (b->address == address) {
            found = i;
            break;
        }
    }
    return found != -1 ? found : -1;
}

static
i64 breakpoint_write_bin(pid_t const pid, size_t const address, u64 const data)
{
    errno = 0;
    u64 peek_data = ptrace(PTRACE_PEEKDATA, pid, address, NULL);
    if (errno != 0) {
        return -1;
    }

    u64 original_data = peek_data & 0xff;
    u64 poke_data = ((peek_data & ~0xff) | (data & 0xff));
    if (ptrace(PTRACE_POKEDATA, pid, address, poke_data) < 0) {
        return -1;
    }

    return (i64)(original_data);
}

static
i32 breakpoint_enable_address(config_t* cfg, size_t const address)
{
    if (cfg->state != DBG_RUNNING) {
        return -1;
    }

    ssize_t id = breakpoint_search(cfg->breakpoints, address);
    if (id < 0) {
        return -1;
    }
    breakpoint_t* b = vec_get(cfg->breakpoints, id);
    if (b->state != BRK_ENABLED) {
        i64 original_data = breakpoint_write_bin(cfg->pid, b->address, INT3);
        if (original_data < 0) {
            return -1;
        }
        b->original_data = (u64)original_data;
        b->state = BRK_ENABLED;
    }

    return 0;
}

static
i32 breakpoint_disable_address(config_t* cfg, size_t const address)
{
    if (cfg->state != DBG_RUNNING) {
        return -1;
    }

    ssize_t id = breakpoint_search(cfg->breakpoints, address);
    if (id < 0) {
        return -1;
    }
    breakpoint_t* b = vec_get(cfg->breakpoints, id);
    if (b->state != BRK_DISABLED) {
        if (breakpoint_write_bin(cfg->pid, b->address, b->original_data) < 0) {
            return -1;
        }
        b->state = BRK_DISABLED;
    }

    return 0;
}

i32 breakpoint_new(config_t* cfg, size_t const address)
{
    if (cfg->state == DBG_UNINIT) {
        printf("%s%serror:%s no target executable currently set.\n", BOLD, RED, NORMAL);
        return -1;
    }

    if (breakpoint_get(cfg->breakpoints, address) != NULL) {
        printf("%s%serror:%s a breakpoint at address 0x%zx already exists.\n",
               BOLD, RED, NORMAL, address);
        return -1;
    }

    i64 original_data = 0;
    if (cfg->state == DBG_RUNNING) {
        original_data = breakpoint_write_bin(cfg->pid, address, INT3);
        if (original_data < 0) {
            return -1;
        }
    }
    
    breakpoint_t self = {
        .address = address,
        .original_data = (u64)original_data,
        .state = cfg->state == DBG_RUNNING ? BRK_ENABLED : BRK_UNINIT,
    };

    i32 ret = vec_push(cfg->breakpoints, &self);
    if (ret != VEC_OK) {
        return -1;
    }

    printf("Breakpoint #%zu set at address 0x%zx.\n", cfg->breakpoints->len, address);
    return ret;
}

breakpoint_t const* breakpoint_get(vec_t const* breakpoints, size_t const address)
{
    ssize_t id = breakpoint_search(breakpoints, address);
    if (id < 0) {
        return NULL;
    }

    // Safe because unreachable if `breakpoint_search` failed
    breakpoint_t const* b = vec_peek(breakpoints, (size_t)id);
    return b;
}

i32 breakpoint_setup(config_t* cfg)
{
    for (size_t i = 0; i < cfg->breakpoints->len; i++) {
        breakpoint_t* b = vec_get(cfg->breakpoints, i);
        if (b->state == BRK_UNINIT) {
            i32 ret = breakpoint_enable_id(cfg, i);
            if (ret < 0) {
                return -1;
            }
        }
    }

    return 0;
}

i32 breakpoint_enable_id(config_t* cfg, size_t const id)
{
    if (cfg->state != DBG_RUNNING) {
        return -1;
    }

    breakpoint_t* b = vec_get(cfg->breakpoints, id);
    if (b->state != BRK_ENABLED) {
        i64 original_data = breakpoint_write_bin(cfg->pid, b->address, INT3);
        if (original_data < 0) {
            return -1;
        }
        b->original_data = original_data;
        b->state = BRK_ENABLED;
    }

    return 0;
}

i32 breakpoint_disable_id(config_t* cfg, size_t const id)
{
    if (cfg->state != DBG_RUNNING) {
        return -1;
    }

    breakpoint_t* b = vec_get(cfg->breakpoints, id);
    if (b->state != BRK_DISABLED) {
        if (breakpoint_write_bin(cfg->pid, b->address, b->original_data) == -1) {
            return -1;
        }
        b->state = BRK_DISABLED;
    }

    return 0;
}

i32 breakpoint_remove_address(config_t* cfg, size_t const address)
{
    if (cfg->state == DBG_UNINIT) {
        printf("%s%serror:%s no target executable currently set.\n", BOLD, RED, NORMAL);
        return -1;
    }

    ssize_t id = breakpoint_search(cfg->breakpoints, address);
    if (id < 0) {
        printf("%swarning:%s no breakpoint set at address 0x%16zx.\n", YELLOW, NORMAL, address); 
        return -1;
    }

    return vec_delete(cfg->breakpoints, id) == VEC_OK ? 0 : -1;
}

i32 breakpoint_remove_id(config_t* cfg, size_t const id)
{
    if (cfg->state == DBG_UNINIT) {
        printf("%s%serror:%s no target executable currently set.\n", BOLD, RED, NORMAL);
        return -1;
    }

    if (id <= cfg->breakpoints->len) {
        printf("%swarning:%s no breakpoint of ID %zu.\n", YELLOW, NORMAL, id); 
        return -1;
    }

    return vec_delete(cfg->breakpoints, id) == VEC_OK ? 0 : -1;
}

i32 breakpoint_step(config_t* cfg)
{
    struct user_regs_struct registers;
    if (ptrace(PTRACE_GETREGS, cfg->pid, NULL, &registers) < 0) {
        return -1;
    }

    u64 address = registers.rip - 1;
    breakpoint_t const* b = breakpoint_get(cfg->breakpoints, address);
    if (!b) {
        return 1;
    }

    // Restore PC address
    registers.rip = address;
    if (ptrace(PTRACE_SETREGS, cfg->pid, NULL, &registers) < 0) {
        return -1;
    }

    if (breakpoint_disable_address(cfg, b->address) < 0) {
        return -1;
    }
    if (ptrace(PTRACE_SINGLESTEP, cfg->pid, NULL, NULL) < 0) {
        return -1;
    }
    debugger_wait_signal(cfg);
    if (breakpoint_enable_address(cfg, b->address) < 0) {
        return -1;
    }

    return 0;
}

void breakpoint_list(config_t const* cfg)
{
    if (vec_is_empty(cfg->breakpoints)) {
        printf("No breakpoints currently set.\n");
        return;
    }

    for (size_t i = 0; i < cfg->breakpoints->len; i++) {
        breakpoint_t const* b = vec_peek(cfg->breakpoints, i);
        printf("Breakpoint #%zu at %s0x%zx%s %s\n", i + 1, YELLOW, b->address, NORMAL,
               b->state != BRK_DISABLED ? "\033[32m(enabled)\033[0m" : "\033[31m(disabled)\033[0m");
    }
}
