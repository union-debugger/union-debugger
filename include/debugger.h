#pragma once

#include <sys/user.h>

#include "types.h"
#include "config.h"

typedef struct {
    int real_mem_curr, real_mem_peak, virt_mem_curr, virt_mem_peak;
} p_mem;

typedef struct {
    int major;
    int minor;
} p_mem_device;

typedef struct {
    char line[500];
    uintptr_t start;
    uintptr_t end;
    unsigned long size;

    int perm;
    bool shared;

    long offset;
    p_mem_device device;
    int inode;

    char path[300];
} p_mem_maps;

ssize_t debugger_run(config_t *cfg, char* const* argv);
ssize_t debugger_wait_signal(config_t* cfg);
ssize_t debugger_cont(config_t* cfg);
ssize_t debugger_kill(config_t* cfg, i32 const signal);
void debugger_print_regs(config_t* cfg);
void debugger_print_mem();
void debugger_pids(config_t* cfg);
void debugger_print_real_path(config_t* cfg);
void debugger_print_mem_maps(config_t* cfg);
