#define _GNU_SOURCE

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <wait.h>

#include <sys/personality.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

#include <libunwind.h>
#include <libunwind-x86_64.h>
#include <libunwind-ptrace.h>

#include "../ext/dwarf.h"
#include "../ext/libdwarf.h"
#include "../ext/vec.h"

#include "../include/breakpoint.h"
#include "../include/debugger.h"
#include "../include/utils.h"
#include "../include/types.h"
#include "../include/config.h"

unw_addr_space_t space;
void* unwind_info;
unw_cursor_t base_cursor;

ssize_t debugger_run(config_t *cfg, char* const* argv)
{
    if (cfg->state == DBG_RUNNING) {
        printf("Inferior process %d is currently being debugged.\n", cfg->pid);
        bool ans = ask_user();
        if (ans) {
            i32 ret = debugger_kill(cfg, SIGKILL);
            UDB_assert(ret <= 0, "failed to kill child process");
        } else {
            printf("Continuing debugging session.\n");
            return 0;
        }
    }

    i32 status = 0;
    char* path = cfg->path;
    char* args[MAX_ARGS + 2];
    args[0] = path;
    memcpy(&args[1], argv, MAX_ARGS * sizeof(char*));
    args[MAX_ARGS + 1] = NULL;

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        personality(ADDR_NO_RANDOMIZE);
        execvp(cfg->path, args);
        printf("%s%serror:%s failed to execute inferior: %s\n", BOLD, RED, NORMAL, strerror(errno));
        abort();
    } else if (pid > 0) {
        cfg->pid = pid;
        cfg->state = DBG_RUNNING;
        space = unw_create_addr_space(&_UPT_accessors, __LITTLE_ENDIAN);
        unwind_info = _UPT_create(pid);

        status = debugger_wait_signal(cfg);
        if (ptrace(PTRACE_SETOPTIONS, cfg->pid, NULL, PTRACE_O_EXITKILL) < 0) {
            return -1;
        }
    } else {
        UDB_assert(false, "fork failed");
    }

    return status;
}

ssize_t debugger_wait_signal(config_t* cfg)
{
    i32 wstatus;

    if (waitpid(cfg->pid, &wstatus, 0) < 0) {
        return -1;
    }
    breakpoint_setup(cfg);

    if (WIFEXITED(wstatus)) {
        printf("Inferior process %d terminated normally (code %d).\n", cfg->pid, WEXITSTATUS(wstatus));
        cfg->state = DBG_LOADED;
    } else if (WIFSIGNALED(wstatus)) {
        i32 signal = WTERMSIG(wstatus);
        printf("Inferior process %d terminated with status %d (%s).\n",
               cfg->pid,
               signal,
               sigdescr_np(signal));
        cfg->state = DBG_LOADED;
    } else if (WIFSTOPPED(wstatus)) {
        // Initialize remote stack unwinding
        unw_init_remote(&base_cursor, space, unwind_info);

        siginfo_t siginfo;
        struct user_regs_struct registers;
        if ((ptrace(PTRACE_GETSIGINFO, cfg->pid, NULL, &siginfo) < 0 ||
            ptrace(PTRACE_GETREGS, cfg->pid, NULL, &registers) < 0) &&
            errno == EINVAL)
        {
            return -1;
        }

        i32 stopsig = WSTOPSIG(wstatus);
        switch (stopsig) {
            case SIGTRAP:
                u64 address = registers.rip - 1;
                breakpoint_t const* b = breakpoint_get(cfg->breakpoints, address);
                if (b) {
                    printf("Inferior stopped at breakpoint (address: %s0x%zx%s).\n",
                           YELLOW, b->address, NORMAL);
                } else {
                    printf("Inferior process %d stopped at entry SIGTRAP.\n", cfg->pid);
                    printf("Type `cont` to resume execution.\n");
                }
                break;
            case SIGSEGV:
            case SIGSTOP:
                printf("Inferior process %d stopped.\n", cfg->pid);
                printf("Name = %s'%s'%s, stopped by signal %sSIG%s (%s)%s at %s0x%llx%s.\n",
                       BOLD, cfg->path, NORMAL,
                       RED, sigabbrev_np(stopsig), sigdescr_np(stopsig), NORMAL,
                       YELLOW, registers.rip, NORMAL);
                break;
            case SIGTSTP:
            case SIGTTIN:
            case SIGTTOU:
                break;
            default: break;
        }
    } else {
        return -1;
    }

    return wstatus;
}

ssize_t debugger_cont(config_t* cfg)
{
    if (cfg->state != DBG_RUNNING) {
        printf("%s%sinfo:%s no target executable is currently running.\n", BOLD, CYAN, NORMAL);
        return -1;
    }

    if (breakpoint_step(cfg) < 0) {
        printf("%s%serror:%s failed to step\n", BOLD, RED, NORMAL);
        return -1;
    }

    if (ptrace(PTRACE_CONT, cfg->pid, NULL, NULL) < 0) {
        printf("%s%serror:%s failed to continue\n", BOLD, RED, NORMAL);
        return -1;
    }

    debugger_wait_signal(cfg);
    return 0;
}

void debugger_pids(config_t* cfg)
{
    if (cfg->state != DBG_RUNNING) {
        printf("Child PID:  %s%s%s\n", BOLD, "None", NORMAL);
    } else {
        printf("Child PID:  %s%d%s\n", BOLD, cfg->pid, NORMAL);
    }
    printf("Child PPID: %s%d%s\n", BOLD, getpid(), NORMAL);
}

void debugger_get_regs(pid_t pid, struct user_regs_struct* regs)
{
    i32 ret = ptrace(PTRACE_GETREGS, pid, 0, regs);
    UDB_assert(ret >= 0, "could not get registers");
}

void debugger_print_regs(config_t* cfg)
{
    if (cfg->state != DBG_RUNNING) {
        printf("%s%serror:%s no target executable is currently running.\n", BOLD, RED, NORMAL);
        return;
    }

    struct user_regs_struct regs;
    debugger_get_regs(cfg->pid, &regs);

    printf("orig_rax: %lld\n", regs.orig_rax); // Last system call
    printf("rax:      %lld\n", regs.rax);
    printf("rbx:      %lld\n", regs.rbx);
    printf("rcx:      %lld\n", regs.rcx);
    printf("rdx:      %lld\n", regs.rdx);
    printf("rsi:      %lld\n", regs.rsi);
    printf("rdi:      %lld\n", regs.rdi);
    printf("r8:       %lld\n", regs.r8);
    printf("r9:       %lld\n", regs.r9);
    printf("r10:      %lld\n", regs.r10);
    printf("r11:      %lld\n", regs.r11);
    printf("r12:      %lld\n", regs.r12);
    printf("r13:      %lld\n", regs.r13);
    printf("r14:      %lld\n", regs.r14);
    printf("r15:      %lld\n", regs.r15);
    printf("rbp:      %lld\n", regs.rbp);
    printf("rsp:      %lld\n", regs.rsp);
    printf("rip:      %lld\n", regs.rip);
    printf("eflags:   %lld\n", regs.eflags);
    printf("cs:       %lld\n", regs.cs);
    printf("ds:       %lld\n", regs.ds);
    printf("es:       %lld\n", regs.es);
    printf("fs:       %lld\n", regs.fs);
    printf("fs_base:  %lld\n", regs.fs_base);
    printf("gs:       %lld\n", regs.gs);
    printf("gs_base:  %lld\n", regs.gs_base);
    printf("ss:       %lld\n", regs.ss);
}

void debugger_get_mem(p_mem* mem)
{
    char buffer[1024];
    FILE* fp_status = fopen("/proc/self/status", "rb");

    while (fscanf(fp_status, " %1023s", buffer) == 1) {
        if (strcmp(buffer, "VmRSS:") == 0) {
            fscanf(fp_status, " %d", &mem->real_mem_curr);
        }
        else if (strcmp(buffer, "VmHWM:") == 0) {
            fscanf(fp_status, " %d", &mem->real_mem_peak);
        }
        else if (strcmp(buffer, "VmSize:") == 0) {
            fscanf(fp_status, " %d", &mem->virt_mem_curr);
        }
        else if (strcmp(buffer, "VmPeak:") == 0) {
            fscanf(fp_status, " %d", &mem->virt_mem_peak);
        }
    }
    fclose(fp_status);
}

void debugger_print_mem()
{
    p_mem mem;
    debugger_get_mem(&mem);
    printf("Memory usage:\n");
    printf("  Current real memory: %s%dB%s\n", BOLD, mem.real_mem_curr, NORMAL);
    printf("  Current virtual memory: %s%dB%s\n", BOLD, mem.virt_mem_curr, NORMAL);
    printf("  Peak real memory: %s%dB%s\n", BOLD, mem.real_mem_peak, NORMAL);
    printf("  Peak virtual memory: %s%dB%s\n", BOLD, mem.virt_mem_peak, NORMAL);
}


/* 
* ELF
* Function gelf_getdyn() retrieves the class - dependent entry at index ndx in data buffer data and copies it to the destination pointed to by argument dyn after translation to class - independent form.
* Reading ELF Header. 
*/

char* strDT(Elf64_Sxword DT_value) {
    switch (DT_value) {
    case DT_NULL:
        return "DT_NULL"; break;
    case DT_NEEDED:
        return "DT_NEEDED"; break;
    case DT_PLTRELSZ:
        return "DT_PLTRELSZ"; break;
    case DT_PLTGOT:
        return "DT_PLTGOT"; break;
    case DT_HASH:
        return "DT_HASH"; break;
    case DT_STRTAB:
        return "DT_STRTAB"; break;
    case DT_SYMTAB:
        return "DT_SYMTAB"; break;
    case DT_RELA:
        return "DT_RELA"; break;
    case DT_RELASZ:
        return "DT_RELASZ"; break;
    case DT_RELAENT:
        return "DT_RELAENT"; break;
    case DT_STRSZ:
        return "DT_STRSZ"; break;
    case DT_SYMENT:
        return "DT_SYMENT"; break;
    case DT_INIT:
        return "DT_INIT"; break;
    case DT_FINI:
        return "DT_FINI"; break;
    case DT_SONAME:
        return "DT_SONAME"; break;
    case DT_RPATH:
        return "DT_RPATH"; break;
    case DT_SYMBOLIC:
        return "DT_SYMBOLIC"; break;
    case DT_REL:
        return "DT_REL"; break;
    case DT_RELSZ:
        return "DT_RELSZ"; break;
    case DT_RELENT:
        return "DT_RELENT"; break;
    case DT_PLTREL:
        return "DT_PLTREL"; break;
    case DT_DEBUG:
        return "DT_DEBUG"; break;
    case DT_TEXTREL:
        return "DT_TEXTREL"; break;
    case DT_JMPREL:
        return "DT_JMPREL"; break;
    case DT_BIND_NOW:
        return "DT_BIND_NOW"; break;
    case DT_INIT_ARRAY:
        return "DT_INIT_ARRAY"; break;
    case DT_FINI_ARRAY:
        return "DT_FINI_ARRAY"; break;
    case DT_INIT_ARRAYSZ:
        return "DT_INIT_ARRAYSZ"; break;
    case DT_FINI_ARRAYSZ:
        return "DT_FINI_ARRAYSZ"; break;
    case DT_RUNPATH:
        return "DT_RUNPATH"; break;
    case DT_FLAGS:
        return "DT_FLAGS"; break;
    case DT_PREINIT_ARRAY:
        return "DT_PREINIT_ARRAY"; break;
    case DT_PREINIT_ARRAYSZ:
        return "DT_PREINIT_ARRAYSZ"; break;
    case DT_SYMTAB_SHNDX:
        return "DT_SYMTAB_SHNDX"; break;
    case DT_NUM:
        return "DT_NUM"; break;
    case DT_LOOS:
        return "DT_LOOS"; break;
    case DT_HIOS:
        return "DT_HIOS"; break;
    case DT_LOPROC:
        return "DT_LOPROC"; break;
    case DT_HIPROC:
        return "DT_HIPROC"; break;
    case DT_PROCNUM:
        return "DT_PROCNUM"; break;
    default:
        return "DT_Unknown";
    }
}

char* strSHT(Elf64_Word SHT_value) {
    switch (SHT_value) {
    case SHT_NULL:
        return "SHT_NULL"; break;
    case SHT_PROGBITS:
        return "SHT_PROGBITS"; break;
    case SHT_SYMTAB:
        return "SHT_SYMTAB"; break;
    case SHT_STRTAB:
        return "SHT_STRTAB"; break;
    case SHT_RELA:
        return "SHT_RELA"; break;
    case SHT_HASH:
        return "SHT_HASH"; break;
    case SHT_DYNAMIC:
        return "SHT_DYNAMIC"; break;
    case SHT_NOTE:
        return "SHT_NOTE"; break;
    case SHT_NOBITS:
        return "SHT_NOBITS"; break;
    case SHT_REL:
        return "SHT_REL"; break;
    case SHT_SHLIB:
        return "SHT_SHLIB"; break;
    case SHT_DYNSYM:
        return "SHT_DYNSYM"; break;
    case SHT_INIT_ARRAY:
        return "SHT_INIT_ARRAY"; break;
    case SHT_FINI_ARRAY:
        return "SHT_FINI_ARRAY"; break;
    case SHT_PREINIT_ARRAY:
        return "SHT_PREINIT_ARRAY"; break;
    case SHT_GROUP:
        return "SHT_GROUP"; break;
    case SHT_SYMTAB_SHNDX:
        return "SHT_SYMTAB_SHNDX"; break;
    case SHT_NUM:
        return "SHT_NUM"; break;
    case SHT_LOOS:
        return "SHT_LOOS"; break;
    case SHT_GNU_ATTRIBUTES:
        return "SHT_GNU_ATTRIBUTES"; break;
    case SHT_GNU_HASH:
        return "SHT_GNU_HASH"; break;
    case SHT_GNU_LIBLIST:
        return "SHT_GNU_LIBLIST"; break;
    case SHT_CHECKSUM:
        return "SHT_CHECKSUM"; break;
    case SHT_LOSUNW:
        return "SHT_LOSUNW"; break;
    case SHT_SUNW_COMDAT:
        return "SHT_SUNW_COMDAT"; break;
    case SHT_SUNW_syminfo:
        return "SHT_SUNW_syminfo"; break;
    case SHT_GNU_verdef:
        return "SHT_GNU_verdef"; break;
    case SHT_GNU_verneed:
        return "SHT_GNU_verneed"; break;
    case SHT_GNU_versym:
        return "SHT_GNU_versym"; break;
    case SHT_LOPROC:
        return "SHT_LOPROC"; break;
    case SHT_HIPROC:
        return "SHT_HIPROC"; break;
    case SHT_LOUSER:
        return "SHT_LOUSER"; break;
    case SHT_HIUSER:
        return "SHT_HIUSER"; break;
    default:
        return "unknown";
    }
}

void debugger_get_libraries(char* path, vec_t* libraries)
{
    UDB_error(elf_version(EV_CURRENT) != EV_NONE, "Lib pb");

    int fd = open(path, O_RDONLY, 0);
    UDB_error(fd >= 0, "Failed to open file");

    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    UDB_error(elf != NULL, "Failed to open elf");
    UDB_error(elf_kind(elf) == ELF_K_ELF, "Provided file does not contain ELF data"); //  Verify it's an ELF file.

    Elf_Scn* scn = NULL; // Elf descriptor

    // Get section with next section index.
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr = {}; // Section Header
        UDB_error(gelf_getshdr(scn, &shdr) == &shdr, "Failed to retrieve section header"); // Retrieve section header

        // printf("Reading section ... %s\n", strSHT(shdr.sh_type));

        if (shdr.sh_type == SHT_DYNAMIC) {
            Elf_Data* data = NULL;
            data = elf_getdata(scn, data);
            UDB_error(data != NULL, "Failed to gather data");

            library lib;

            size_t sh_entsize = gelf_fsize(elf, ELF_T_DYN, 1, EV_CURRENT);

            for (size_t i = 0; i < shdr.sh_size / sh_entsize; i++) {
                vec_push(libraries, &lib);
                GElf_Dyn dyn = {};
                UDB_error(gelf_getdyn(data, i, &dyn) == &dyn, "Failed to retrieve section");

                char* res = malloc(sizeof(char) * strlen(strDT(dyn.d_tag)));
                strcpy(res, strDT(dyn.d_tag));
                lib.strtype = strdup(res + 3);
                free(res);

                if (dyn.d_tag == DT_NEEDED) lib.name = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                else lib.name = NULL;

                lib.addr = dyn.d_un.d_ptr;
                lib.type = dyn.d_tag;

                VEC_MUT(libraries, library, libraries->capacity - 1, lib);
                vec_resize(libraries, libraries->capacity + 1);
            }
        }
    }
    UDB_error(elf_end(elf) == 0, "Failed to close ELF");
    UDB_error(close(fd) == 0, "Failed to close file");
}


void debugger_print_libraries(config_t* cfg)
{
    if (cfg->state != DBG_RUNNING) {
        printf("%s%serror:%s no target executable is currently running.\n", BOLD, RED, NORMAL);
        return;
    }

    vec_t* libraries = vec_with_capacity(1, sizeof(library));
    char real_path[BUFFER_LEN];
    debugger_get_real_path(cfg->pid, real_path);
    
    debugger_get_libraries(real_path, libraries);

    for (size_t i = 0; i < libraries->len; i++) {
        library* lib = (library*)vec_peek(libraries, i);
        if (lib->type == DT_NEEDED)
            printf("0x%010lx (%s) \t \t[%s]\n", lib->addr, lib->strtype, lib->name);
        else
            printf("0x%010lx (%s)\n", lib->addr, lib->strtype);
    }
}

void debugger_print_shared_libraries(config_t* cfg)
{
    if (cfg->state != DBG_RUNNING) {
        printf("%s%serror:%s no target executable is currently running.\n", BOLD, RED, NORMAL);
        return;
    }

    vec_t* libraries = vec_with_capacity(1, sizeof(library));
    char real_path[BUFFER_LEN];
    debugger_get_real_path(cfg->pid, real_path);

    debugger_get_libraries(real_path, libraries);

    for (size_t i = 0; i < libraries->len; i++) {
        library* lib = (library*)vec_peek(libraries, i);
        if (lib->type == DT_NEEDED)
            printf("0x%010lx (%s) \t \t[%s]\n", lib->addr, lib->strtype, lib->name);
    }
}

/*
* Libdwarf
* Reading the .debug_str
*/

int get_debug_strings(Dwarf_Debug dbg, Dwarf_Error* err, vec_t* dstr)
{
    Dwarf_Off offset;
    Dwarf_Signed len;
    char* str;
    int ret;
    offset = 0;

    int i = 0;
    debug_str dst;

    while ((ret = dwarf_get_str(dbg, offset, &str, &len, err)) == DW_DLV_OK) {
        vec_push(dstr, &dst);
        offset += len + 1;

        dst.offset = offset;
        dst.len = len;

        strcpy(dst.str, str);

        VEC_MUT(dstr, debug_str, dstr->capacity - 1, dst);
        int ret = vec_resize(dstr, dstr->capacity + 1);
        UDB_assert(ret == VEC_OK, "failed to resize vector");
        i++;
    }
    if (i == 0) {
    }
    UDB_error(!(ret == DW_DLV_NO_ENTRY), "This executable does not contains debug info");
    UDB_error((ret == DW_DLV_ERROR), dwarf_errmsg(*err));
    UDB_error(!(ret == DW_DLV_ERROR), dwarf_errmsg(*err));
    // DW_DLV_NO_ENTRY
    // DW_DLV_ERROR
    return 0;
}

void debugger_print_debug_strings(config_t* cfg)
{
    if (cfg->state != DBG_RUNNING) {
        printf("%s%serror:%s no target executable is currently running.\n", BOLD, RED, NORMAL);
        return;
    }

    vec_t* dstr = vec_with_capacity(1, sizeof(debug_str));

    dwarf_dbg ddbg;
    ddbg.errhand = 0;
    ddbg.tpathlen = FILENAME_MAX;
    ddbg.errarg = 0;
    ddbg.error = 0;
    ddbg.dbg = 0;
    ddbg.groupnumber = DW_GROUPNUMBER_ANY;
    int res = 0;

    char real_path[150];

    debugger_get_real_path(cfg->pid, real_path);

    res = dwarf_init_path(real_path, ddbg.true_pathbuf, ddbg.tpathlen, ddbg.groupnumber, ddbg.errhand, ddbg.errarg, &ddbg.dbg, &ddbg.error);

    if (res == DW_DLV_ERROR) dwarf_dealloc_error(ddbg.dbg, ddbg.error);
    UDB_error(!(res == DW_DLV_ERROR), dwarf_errmsg(ddbg.error));

    UDB_error(!(res == DW_DLV_NO_ENTRY), "This executable does not contain any debug info");

    get_debug_strings(ddbg.dbg, &ddbg.error, dstr);

    for (size_t i = 0; i < dstr->len; i++) {
        debug_str* dst = (debug_str*)vec_peek(dstr, i);
        printf("name at offset 0x%05llx, length % 6lld is '%s'\n", dst->offset, dst->len, dst->str);
    }

    dwarf_finish(ddbg.dbg);
}


/*
* DEBUGGER BACKTRACE
* using libunwind
*/

void debugger_backtrace(int dbg_state)
{
    if (dbg_state != DBG_RUNNING) {
        printf("No backtrace.\n");
        printf("%s%sinfo:%s no target executable is currently running.\n", BOLD, CYAN, NORMAL);
        return;
    }
    unw_word_t ip, sp, offset;
    unw_cursor_t cursor = base_cursor;
    char funcname[128];
    size_t frame = 0;
    while (unw_step(&cursor) > 0) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        unw_get_proc_name(&cursor, funcname, sizeof(funcname), &offset);
        printf("* frame %s#%zu%s --> %s0x%lx%s, rsp = %s0x%lx%s at %s%s%s (+%lu)\n",
               GREEN, frame, NORMAL,
               YELLOW, ip, NORMAL, YELLOW, sp, NORMAL, BLUE, funcname, NORMAL, offset);
        frame++;
    }
}

/*
** Memory Maps

* Not able to get maps elsewhere than in the /proc

* start & end of memory address of the contigeous virtual memory
* Permissions : can be [r]ead, [w]rite, e[x]ecuted. If region not [s]hared, it's [p]rivate.
* Segfault occurs if process attemps to access memory in a non expected way.
* Permissions can be changed using the mprotect system call.
* Offset : If memory is mapped from a file, offset is the offset from where to read. If not from a file, it's 0
* [dev]ive in /dev/ * represent it's driver ID (major) and a (minor) metadata used by the related driver to identify the block.
* pathname : the file readed, if any. Can also be - [stack] for main thread's stack
*                                                 - [stack:tid] stack for a specific Thread ID
*                                                 - [vdso] virtual dynamically linked shared object. When using standard functions, defined in the C library, they are called from the kernel, which can be very slow. To avoid this, we load the library in the environment of each program using its auxiliary vector. (ELF) (AT_SYSINFO_EHDR tag) // can be shown LD_SHOW_AUXV=1 /bin/true
*/

// void debugger_get_mem_maps(p_mem_maps* p_mmaps, int inferior_pid)
int debugger_get_mem_maps(vec_t* p_mmaps, int inferior_pid)
{
    char path[BUFFER_LEN];
    snprintf(path, sizeof(path), "/proc/%u/maps", inferior_pid);
    FILE* fp = fopen(path, "r");
    UDB_assert(fp, "failed to read memory maps");

    char* buff = NULL;
    size_t buff_size = 0;
    i8 nm = 0; // Number of memory maps
    p_mem_maps map;

    while (getline(&buff, &buff_size, fp) != -1) {
        vec_push(p_mmaps, &map);
        // memcpy(map.line, strtok(buff, "\n"), buff_size);
        sprintf(map.line, strtok(buff, "\n"));
        char* buff_start = strtok(buff, "-");
        char* buff_end = strtok(NULL, " ");
        char* buff_perm = strtok(NULL, " ");
        char* buff_offset = strtok(NULL, " ");
        char* buff_dev_major = strtok(NULL, ":");
        char* buff_dev_minor = strtok(NULL, " ");
        char* buff_inode = strtok(NULL, " ");
        char* buff_path = strtok(NULL, " ");

        // Start, end and size are integers, instead of hexa.
        map.start = strtoul(buff_start, NULL, 16);
        map.end = strtoul(buff_end, NULL, 16);
        map.size = map.end - map.start;

        map.perm = 0;
        if (buff_perm[0] == 'r') map.perm |= 0x04;
        if (buff_perm[1] == 'w') map.perm |= 0x02;
        if (buff_perm[2] == 'x') map.perm |= 0x01;
        map.shared = buff_perm[3] == 'p' ? false : true;

        // map.offset = strtoul(buff_offset, NULL, 16);
        map.offset = atoi(buff_offset);
        map.device.major = strtoul(buff_dev_major, NULL, 10);
        map.device.minor = strtoul(buff_dev_minor, NULL, 10);
        map.inode = atoi(buff_inode);

        if (buff_path) {
            strcpy(map.path, buff_path);
        }

        VEC_MUT(p_mmaps, p_mem_maps, p_mmaps->capacity-1, map);
        int ret = vec_resize(p_mmaps, p_mmaps->capacity+1);
        UDB_assert(ret == VEC_OK, "failed to resize vector");
        nm++;
    }
    fclose(fp);
    return 0;
}

void debugger_print_mem_maps(config_t* cfg)
{
    if (cfg->state != DBG_RUNNING) {
        printf("%s%serror:%s no target executable is currently running.\n", BOLD, RED, NORMAL);
        return;
    }

    vec_t* p_mmaps = vec_with_capacity(1, sizeof(p_mem_maps));

    debugger_get_mem_maps(p_mmaps, cfg->pid);
    for (size_t i = 0; i < p_mmaps->len; i++) {
        p_mem_maps* map = (p_mem_maps*)vec_peek(p_mmaps, i);
        printf("%s\n", map->line);
        // printf("%ld-%ld %d%s %ld   %d:%d %d \t\t%s\n", map->start, map->end, map->perm, map->shared == true ? "s" : "p", map->offset, map->device.major, map->device.minor, map->inode, map->path);
    }
}

void debugger_get_real_path(pid_t pid, char* real_path)
{
    char proc_addr[BUFFER_LEN];
    sprintf(proc_addr, "/proc/%d/exe", pid);
    ssize_t ret = readlink(proc_addr, real_path, BUFFER_LEN);
    UDB_assert(ret >= 0, "failed to read real path");
}

void debugger_print_real_path(config_t* cfg)
{
    char real_path[BUFFER_LEN];
    if (cfg->state != DBG_RUNNING) {
        printf("%s%serror:%s no target executable is currently running.\n", BOLD, RED, NORMAL);
        return;
    }
    debugger_get_real_path(cfg->pid, real_path);
    printf("Real path: %s%s%s.\n", BOLD, real_path, NORMAL);
}

ssize_t debugger_kill(config_t* cfg, i32 const signal)
{
    if (cfg->state != DBG_RUNNING) {
        printf("%s%serror:%s no target executable is currently running.\n", BOLD, RED, NORMAL);
        return -1;
    }

    i32 ret = kill(cfg->pid, signal);
    if (ret < 0) {
#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 32
        printf("%s%serror:%s failed to send signal SIG%s to process %d\n",
               BOLD, RED, NORMAL, sigabbrev_np(signal), cfg->pid);
#else
        printf("%s%serror:%s failed to send signal to process %d\n",
               BOLD, RED, NORMAL, cfg->pid);
#endif
    }
    printf("Sent signal SIG%s to process %d.\n", sigabbrev_np(signal), cfg->pid);
    cfg->state = DBG_LOADED;
    cfg->pid = 0;

    // Zombie child assertion
    ret = waitpid(cfg->pid, NULL, WNOHANG);
    kill(getpid(), SIGCHLD);
    UDB_assert(ret >= 0, "child process is a zombie");

    return ret;
}
