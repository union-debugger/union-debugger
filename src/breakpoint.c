#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "../include/breakpoint.h"
#include "../include/consts.h"
#include "../include/debugger.h"
#include "../include/utils.h"

#define INT3 0xcc

static
ssize_t breakpoint_search(vec_t* breakpoints, size_t const address)
{
    breakpoint_t b;
    ssize_t found = -1;
    for (size_t i = 0; i < breakpoints->len; i++) {
        b = *(breakpoint_t*)(vec_peek(breakpoints, i));
        if (b.address == address) {
            found = i;
            break;
        }
    }
    return found != -1 ? found : -1;
}

breakpoint_t* breakpoint_peek(vec_t* breakpoints, size_t const address)
{
    breakpoint_t* b;
    ssize_t found = -1;
    for (size_t i = 0; i < breakpoints->len; i++) {
        b = (breakpoint_t*)(vec_peek(breakpoints, i));
        if (b->address == address) {
            found = i;
            break;
        }
    }
    return found != -1 ? b : NULL;
}

static
i64 breakpoint_write_bin(config_t* cfg, size_t const address, u64 const data)
{
    errno = 0;
    u64 peek_data = ptrace(PTRACE_PEEKDATA, cfg->pid, address, NULL);
    if (errno != 0) {
        return -1;
    }

    u64 original_data = peek_data & 0xff;
    u64 poke_data = ((peek_data & ~0xff) | (data & 0xff));
    if (ptrace(PTRACE_POKEDATA, cfg->pid, address, poke_data) < 0) {
        return -1;
    }

    return (u64)(original_data);
}

static
i32 breakpoint_enable_address(config_t* cfg, size_t const address)
{
    if (cfg->state != STATE_RUNNING) {
        return -1;
    }

    ssize_t id = breakpoint_search(cfg->breakpoints, address);
    if (id < 0) {
        return -1;
    }
    breakpoint_t* b = vec_peek(cfg->breakpoints, id);
    if (!b->is_enabled) {
        i64 original_data = breakpoint_write_bin(cfg, b->address, INT3);
        if (original_data < 0) {
            return -1;
        }
        b->original_data = original_data;
        b->is_enabled = true;
    }

    return 0;
}

static
i32 breakpoint_disable_address(config_t* cfg, size_t const address)
{
    if (cfg->state != STATE_RUNNING) {
        return -1;
    }

    ssize_t id = breakpoint_search(cfg->breakpoints, address);
    if (id < 0) {
        return -1;
    }
    breakpoint_t* b = vec_peek(cfg->breakpoints, id);
    if (b->is_enabled) {
        if (breakpoint_write_bin(cfg, b->address, b->original_data) == -1) {
            return -1;
        }
        b->is_enabled = false;
    }

    return 0;
}

i32 breakpoint_new(config_t* cfg, size_t const address)
{
    if (cfg->state != STATE_RUNNING) {
        printf("%sinfo:%s debugger is not running\n", MAGENTA, NORMAL);
        return -1;
    }

    if (breakpoint_peek(cfg->breakpoints, address) != NULL) {
        printf("%sinfo:%s a breakpoint at address 0x%zx already exists\n",
               MAGENTA, NORMAL, address);
        return -1;
    }

    i64 original_data = breakpoint_write_bin(cfg, address, INT3);
    if (original_data < 0) {
        return -1;
    }

    breakpoint_t self = {
        .address = address,
        .original_data = original_data,
        .is_enabled = true,
    };

    i32 ret = vec_push(cfg->breakpoints, &self);
    if (ret != VEC_OK) {
        return -1; 
    }

    printf("%sinfo:%s breakpoint #%zu set at address 0x%zx\n", MAGENTA, NORMAL, cfg->breakpoints->len, address);
    return ret;
}

i32 breakpoint_enable_id(config_t* cfg, size_t const id)
{
    if (cfg->state != STATE_RUNNING) {
        return -1;
    }

    breakpoint_t* b = vec_peek(cfg->breakpoints, id);
    if (!b->is_enabled) {
        i64 original_data = breakpoint_write_bin(cfg, b->address, INT3);
        if (original_data < 0) {
            return -1;
        }
        b->original_data = original_data;
        b->is_enabled = true;
    }

    return 0;
}

i32 breakpoint_disable_id(config_t* cfg, size_t const id)
{
    if (cfg->state != STATE_RUNNING) {
        return -1;
    }

    breakpoint_t* b = vec_peek(cfg->breakpoints, id);
    if (b->is_enabled) {
        if (breakpoint_write_bin(cfg, b->address, b->original_data) == -1) {
            return -1;
        }
        b->is_enabled = false;
    }

    return 0;
}

i32 breakpoint_remove_address(config_t* cfg, size_t const address)
{
    if (cfg->state == STATE_UNINIT) {
        printf("%sinfo:%s debugger has not been initialized yet\n", MAGENTA, NORMAL);
        return -1;
    }

    for (size_t i = 0; i < cfg->breakpoints->len; i++) {
        breakpoint_t* current = vec_peek(cfg->breakpoints, i);
        if (current->address == address) {
            return vec_delete(cfg->breakpoints, i) == 0 ? 0 : -1;
        }
    }

    printf("%swarning:%s no breakpoint set at address 0x%16zx\n", YELLOW, NORMAL, address); 
    return -1;
}

i32 breakpoint_remove_id(config_t* cfg, size_t const id)
{
    if (cfg->state == STATE_UNINIT) {
        printf("%sinfo:%s debugger has not been initialized yet\n", MAGENTA, NORMAL);
        return -1;
    }

    if (id <= cfg->breakpoints->len) {
        printf("%swarning:%s no breakpoint of ID %zu\n", YELLOW, NORMAL, id); 
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
    breakpoint_t* b = breakpoint_peek(cfg->breakpoints, address);
    if (!b) {
        return 0;
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

    return 1;
}

void breakpoint_list(config_t* cfg)
{
    if (vec_is_empty(cfg->breakpoints)) {
        printf("No breakpoints set\n");
        return;
    }

    for (size_t i = 0; i < cfg->breakpoints->len; i++) {
        breakpoint_t* b = vec_peek(cfg->breakpoints, i);
        printf("Breakpoint #%zu at 0x%zx %s\n", i + 1, b->address,
               b->is_enabled == true ? "\033[32m(enabled)\033[0m" : "\033[31m(disabled)\033[0m");
    }
}
