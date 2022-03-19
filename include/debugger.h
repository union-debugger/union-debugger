#pragma once

#include <sys/user.h>

#include "types.h"
#include "config.h"

typedef struct {
    int real_mem_curr, real_mem_peak, virt_mem_curr, virt_mem_peak;
} p_mem;

i32 exec_inferior(char const* path, char* const* args);
i32 debug_run(config_t *cfg, char* const* argv);

i32 debug_capture_signal(config_t* cfg);

void debug_get_regs(i8 child, struct user_regs_struct* regs);
void debug_print_regs(config_t* cfg);

void debug_get_mem(p_mem* mem);
void debug_print_mem();

i8 debug_kill(config_t* cfg, char const* args);

void debug_print_pids();
void debug_print_child_pids(config_t* cfg);

void debug_print_real_path(config_t* cfg);


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

void debug_print_mem_maps(int inferior_pid);
