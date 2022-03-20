#pragma once

#include <sys/user.h>

#include "../ext/dwarf.h"
#include "../ext/libdwarf.h"

#include "types.h"
#include "config.h"
#include "consts.h"

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

typedef struct {
    char true_pathbuf[FILENAME_MAX];
    unsigned tpathlen;
    Dwarf_Handler errhand;
    Dwarf_Ptr errarg;
    Dwarf_Error error;
    Dwarf_Debug dbg;
    unsigned groupnumber;
} dwarf_dbg;

typedef struct {
    Dwarf_Off offset;
    Dwarf_Signed len;
    char str[BUFFER_LEN_MAX];
} debug_str;

// typedef struct {
//     Elf* elf; // ELF 
//     Elf_Scn* scn; // ELF descriptor
//     GElf_Shdr shdr; // Section Header
//     Elf_Data* data; // Section Data
// }elf_data;

typedef struct {
    uint64_t addr;
    int64_t type;
    char* strtype;
    char* name;
}library;

ssize_t debugger_run(config_t *cfg, char* const* argv);
ssize_t debugger_wait_signal(config_t* cfg);
ssize_t debugger_cont(config_t* cfg);
ssize_t debugger_kill(config_t* cfg, i32 const signal);
void debugger_print_regs(config_t* cfg);
void debugger_print_mem();
void debugger_pids(config_t* cfg);
void debugger_get_real_path(pid_t pid, char* real_path);
void debugger_print_real_path(config_t* cfg);
void debugger_print_mem_maps(config_t* cfg);
void debugger_backtrace(pid_t inferior_pid);
void debugger_print_debug_strings(config_t* cfg);
void debugger_print_libraries(config_t* cfg);
void debugger_print_shared_libraries(config_t* cfg);