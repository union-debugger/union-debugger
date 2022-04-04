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
#include<sys/stat.h>

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
            errno == EINVAL){
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
            case SIGABRT:
            case SIGFPE:
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
            default:break;
        }
    } else {
        return -1;
    }

    return wstatus;
}

ssize_t debugger_cont(config_t* cfg)
{
    UDB_user_error(cfg->state == DBG_RUNNING, "no target executable is currently running.");

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
    UDB_user_error(cfg->state == DBG_RUNNING, "no target executable is currently running.");

    struct user_regs_struct regs;
    debugger_get_regs(cfg->pid, &regs);

    printf("General Purposes Registers\n");

    printf("%sRegister    %sAddress/Value   %sReference%s\n\n", BOLD, YELLOW, CYAN, NORMAL);

    printf("orig_rax  %s             %lld   %s%s%s\n",
        YELLOW, regs.orig_rax, CYAN, syscall_tab[regs.orig_rax], NORMAL); // Last system call
    printf("     rax  %s 0x%012lx %s\n", YELLOW, regs.rax, NORMAL);
    printf("     rbx  %s 0x%012lx %s\n", YELLOW, regs.rbx, NORMAL);
    printf("     rcx  %s 0x%012lx %s\n", YELLOW, regs.rcx, NORMAL);
    printf("     rdx  %s 0x%012lx %s\n", YELLOW, regs.rdx, NORMAL);
    printf("     rsi  %s 0x%012lx %s\n", YELLOW, regs.rsi, NORMAL);
    printf("     rdi  %s 0x%012lx %s\n", YELLOW, regs.rdi, NORMAL);
    printf("      r8  %s 0x%012lx %s\n", YELLOW, regs.r8, NORMAL);
    printf("      r9  %s 0x%012lx %s\n", YELLOW, regs.r9, NORMAL);
    printf("     r10  %s 0x%012lx %s\n", YELLOW, regs.r10, NORMAL);
    printf("     r11  %s 0x%012lx %s\n", YELLOW, regs.r11, NORMAL);
    printf("     r12  %s 0x%012lx %s\n", YELLOW, regs.r12, NORMAL);
    printf("     r13  %s 0x%012lx %s\n", YELLOW, regs.r13, NORMAL);
    printf("     r14  %s 0x%012lx %s\n", YELLOW, regs.r14, NORMAL);
    printf("     r15  %s 0x%012lx %s\n", YELLOW, regs.r15, NORMAL);
    printf("     rbp  %s 0x%012lx %s\n", YELLOW, regs.rbp, NORMAL);
    printf("     rsp  %s 0x%012lx %s\n", YELLOW, regs.rsp, NORMAL);
    printf("     rip  %s 0x%012lx %s\n", YELLOW, regs.rip, NORMAL);
    printf("  eflags  %s 0x%012lx %s\n", YELLOW, regs.eflags, NORMAL);
    printf("      cs  %s 0x%012lx %s\n", YELLOW, regs.cs, NORMAL);
    printf("      ds  %s 0x%012lx %s\n", YELLOW, regs.ds, NORMAL);
    printf("      es  %s 0x%012lx %s\n", YELLOW, regs.es, NORMAL);
    printf("      fs  %s 0x%012lx %s\n", YELLOW, regs.fs, NORMAL);
    printf(" fs_base  %s 0x%012lx %s\n", YELLOW, regs.fs_base, NORMAL);
    printf("      gs  %s 0x%012lx %s\n", YELLOW, regs.gs, NORMAL);
    printf(" gs_base  %s 0x%012lx %s\n", YELLOW, regs.gs_base, NORMAL);
    printf("      ss  %s 0x%012lx %s\n", YELLOW, regs.ss, NORMAL);
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

int debugger_get_libraries(char* path, vec_t* libraries)
{
    UDB_error(elf_version(EV_CURRENT) != EV_NONE, "Lib pb");

    int fd = open(path, O_RDONLY, 0);
    UDB_error(fd >= 0, "Failed to open file\n The program may have been signaled already :(");

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


char* ELF_get_section_name(Elf* elf, GElf_Shdr shdr) {
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        printf("elf_getshdrstrndx failed : %s.", elf_errmsg(-1));

    char* section_name = elf_strptr(elf, shstrndx, shdr.sh_name);
    UDB_error(section_name, "Failed to get ELF section name");
    return section_name;
}


char* strSYM_STVISIBILITY(unsigned char STV_value) {
    // STV_DEFAULT 0x00 - which means this is the default visibility rules
    // STV_INTERNAL 0x01 - Processor specific hidden class
    // STV_HIDDEN 0x02 - means this symbol is not available for reference in other modules
    // STV_PROTECTED 0x03 - Documentation refers to this as a protected symbol.I believe the only thing that differs between this and a normal STV_DEFAULT symbols is that it won't be allowed to be overridden when referenced from within its own shared library.

    /* Symbol visibility specification encoded in the st_other field.  */
    switch (ELF64_ST_VISIBILITY(STV_value)) {
    case STV_DEFAULT:            		/* Default symbol visibility rules */
        return "STV_DEFAULT"; break;
    case STV_INTERNAL:           		/* Processor specific hidden class */
        return "STV_INTERNAL"; break;
    case STV_HIDDEN:         		/* Sym unavailable in other modules */
        return "STV_HIDDEN"; break;
    case STV_PROTECTED:          		/* Not preemptible, not exported */
        return "STV_PROTECTED"; break;
    default:
        return "STV_Unknown";
    }
}

char* strSYM_STSCOPE(unsigned char STT_value) {
    switch ELF64_ST_BIND(STT_value) {
    case STB_LOCAL: 		/* Local symbol */
        return "STB_LOCAL"; break;
    case STB_GLOBAL:    		/* Global symbol */
        return "STB_GLOBAL"; break;
    case STB_WEAK:  		/* Weak symbol */
        return "STB_WEAK"; break;
    case STB_NUM:   		/* Number of defined types.  */
        return "STB_NUM"; break;
        // case STB_LOOS:  		/* Start of OS-specific */
        //     return "STB_LOOS"; break;
    case STB_GNU_UNIQUE:    		/* Unique symbol.  */
        return "STB_GNU_UNIQUE"; break;
        // case STB_HIOS:  		/* End of OS-specific */
        //     return "STB_HIOS"; break;
        // case STB_LOPROC:    		/* Start of processor-specific */
        //     return "STB_LOPROC"; break;
        // case STB_HIPROC:    		/* End of processor-specific */
        //     return "STB_HIPROC"; break;
    default:
        return "STB_Unknown";
    }
}

char* strSYM_STTYPE(unsigned char STT_value) {
    switch (ELF64_ST_TYPE(STT_value)) {
    case STT_NOTYPE:             /* Symbol type is unspecified */
        return "STT_NOTYPE"; break;
    case STT_OBJECT:             /* Symbol is a data object */
        return "STT_OBJECT"; break;
    case STT_FUNC:               /* Symbol is a code object */
        return "STT_FUNC"; break;
    case STT_SECTION:                /* Symbol associated with a section */
        return "STT_SECTION"; break;
    case STT_FILE:               /* Symbol's name is file name */
        return "STT_FILE"; break;
    case STT_COMMON:             /* Symbol is a common data object */
        return "STT_COMMON"; break;
    case STT_TLS:                /* Symbol is thread-local data object*/
        return "STT_TLS"; break;
    case STT_NUM:                /* Number of defined types.  */
        return "STT_NUM"; break;
        // case STT_LOOS:               /* Start of OS-specific */
        //     return "STT_LOOS"; break;
    case STT_GNU_IFUNC:              /* Symbol is indirect code object */
        return "STT_GNU_IFUNC"; break;
        // case STT_HIOS:               /* End of OS-specific */
        //     return "STT_HIOS"; break;
        // case STT_LOPROC:             /* Start of processor-specific */
        //     return "STT_LOPROC"; break;
        // case STT_HIPROC:             /* End of processor-specific */
        //     return "STT_HIPROC"; break;
    default:
        return "STT_Unknown";
    }
}


void debugger_get_symtab(char* path, vec_t* s_syms) {
    UDB_error(elf_version(EV_CURRENT) != EV_NONE, "The ELF Library version is outdated");

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
        // char* section_name = ELF_get_section_name(elf, shdr);
        // printf("Reading section ... %s (%ld)\n", section_name, shdr.sh_size);

        if (shdr.sh_type == SHT_SYMTAB) {
            // typedef struct {
            // Elf64_Word st_name;  /* (4 bytes) Symbol name  unsigned int  */
            // unsigned char st_info;  /* (1 byte) Symbol type and binding */
            // unsigned char st_other; /* (1 byte) Symbol visibility */
            // Elf64_Section st_shndx; /* (2 bytes) Section index unsigned short int*/
            // Elf64_Addr st_value; /* (8 bytes) Symbol value unsigned long int */
            // Elf64_Xword st_size; /*  (8 bytes) Symbol size unsigned long int */
            // } Elf64_Sym;

            /*
            * SHT_SYMTAB
            * The symbol table holds information needed to locateand relocate a program's definitions and symbolic references
            *
            * st_value Value of the symbol this has different interpretations depending on the symbol type :
            * In executable filesand shared objects this file holds the virtual address for the symbol's definition.
            *     For relocatable files this value will for the most part indicate the offset for where the symbol is defined.
            *     For Symbols who's st_shndx is a SHN_COMMON, st_value will hold alignment constraints for when its relocated.
            *     st_size  Size of of the symbol, indicates how many bytes will be occupied by what this symbol represents depending again on symbol type - for the * most part either the size of the data field for a variable or the size of code for a function.
            */

            Elf_Data* data = NULL;
            data = elf_getdata(scn, data);
            UDB_error(data != NULL, "Failed to gather data");

            size_t sh_entsize = gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT);

            symtab s_sym;

            for (size_t i = 0; i < shdr.sh_size / sh_entsize; i++) {

                GElf_Sym sym = {};
                UDB_error(gelf_getsym(data, i, &sym) == &sym, "Failed to retrieve section");

                if ((sym.st_name == 0) || (sym.st_shndx == SHN_UNDEF))
                    continue;

                vec_push(s_syms, &s_sym);

                // printf("% 50s\t(%02d) % 10s - % 10s\t(%02d) % 20s \t| value : %ld size : %ld\n", sym_name, sym.st_info, strSYM_STSCOPE(sym.st_info), strSYM_STTYPE(sym.st_info), sym.st_other, strSYM_STVISIBILITY(sym.st_other), sym.st_value, sym.st_size);

                s_sym.st_name = sym.st_name;
                s_sym.name = strdup(elf_strptr(elf, shdr.sh_link, sym.st_name));
                s_sym.st_info = sym.st_info;
                s_sym.scope = strSYM_STSCOPE(sym.st_info);
                s_sym.type = strSYM_STTYPE(sym.st_info);
                s_sym.st_other = sym.st_other;
                s_sym.visibility = strSYM_STVISIBILITY(sym.st_other);
                s_sym.st_value = sym.st_value;
                s_sym.st_size = sym.st_size;

                // st_value Value of the symbol this has different interpretations depending on the symbol type :
                // In executable filesand shared objects this file holds the virtual address for the symbol's definition.
                //     For relocatable files this value will for the most part indicate the offset for where the symbol is defined.
                //     For Symbols who's st_shndx is a SHN_COMMON, st_value will hold alignment constraints for when its relocated.
                //     st_size  Size of of the symbol, indicates how many bytes will be occupied by what this symbol represents depending again on symbol type - for the most part either the size of the data field for a variable or the size of code for a function.

                VEC_MUT(s_syms, symtab, s_syms->len - 1, s_sym);
            }
        }
    }
    UDB_error(elf_end(elf) == 0, "Failed to close ELF");
    UDB_error(close(fd) == 0, "Failed to close file");
}

void debugger_print_symtab(config_t* cfg) {
    char real_path[BUFFER_LEN];
    debugger_get_real_path(cfg, real_path);
    UDB_error((real_path != NULL), "Cannot retrieve program's path");

    vec_t* s_syms = vec_with_capacity(1, sizeof(symtab));
    
    debugger_get_symtab(real_path, s_syms);


    printf("%s%s% 50s%s%s     %s  %s  %s     %s% 12s%s%s    %s%s\n\n",
        BOLD, CYAN, "Name", NORMAL, BOLD,
        "  Scope  ", "     Type  ", "Visibility",
        YELLOW, "Address", NORMAL, BOLD, "Var size", NORMAL);

    for (size_t i = 0; i < s_syms->len; i++) {
        symtab* s_sym = (symtab*)vec_peek(s_syms, i);

        printf("%s% 50s%s    %s% 8s%s    % 9s    %s% 9s      %s0x%010lx%s",
            LIGHTCYAN, s_sym->name, NORMAL,
            (ELF64_ST_BIND(s_sym->st_info) == STB_GLOBAL) ? GREEN : NORMAL, s_sym->scope + 4, NORMAL,
            s_sym->type + 4,
            (ELF64_ST_VISIBILITY(s_sym->st_other) != STV_DEFAULT) ? RED : NORMAL, s_sym->visibility + 4,
            YELLOW, s_sym->st_value, NORMAL);
        if (s_sym->st_size != 0) printf("    %ld\n", s_sym->st_size);
        else printf("\n");
    }
}

void debugger_print_functions(config_t* cfg) {
    char real_path[BUFFER_LEN];
    debugger_get_real_path(cfg, real_path);
    UDB_error((real_path != NULL), "Cannot retrieve program's path");

    vec_t* s_syms = vec_with_capacity(1, sizeof(symtab));
    debugger_get_symtab(real_path, s_syms);

    printf("%s%s% 50s%s%s     %s  %s      %s% 12s%s%s    %s%s\n\n",
        BOLD, CYAN, "Name", NORMAL, BOLD,
        "  Scope  ", "Visibility",
        YELLOW, "Address", NORMAL,
        BOLD, "Var size", NORMAL);
    for (size_t i = 0; i < s_syms->len; i++) {
        symtab* s_sym = (symtab*)vec_peek(s_syms, i);

        if (ELF64_ST_TYPE(s_sym->st_info) == STT_FUNC) {
            printf("%s% 50s%s    %s% 8s%s     %s% 9s      %s0x%010lx%s",
                LIGHTCYAN, s_sym->name, NORMAL,
                (ELF64_ST_BIND(s_sym->st_info) == STB_GLOBAL) ? GREEN : NORMAL, s_sym->scope + 4, NORMAL,
                (ELF64_ST_VISIBILITY(s_sym->st_other) != STV_DEFAULT) ? RED : NORMAL, s_sym->visibility + 4,
                YELLOW, s_sym->st_value, NORMAL);
            if (s_sym->st_size != 0) printf("	  %ld\n", s_sym->st_size);
            else printf("\n");
        }
    }
}

void debugger_print_variables(config_t* cfg)
{
    char real_path[BUFFER_LEN];
    debugger_get_real_path(cfg, real_path);
    UDB_error((real_path != NULL), "Cannot retrieve program's path");

    vec_t* s_syms = vec_with_capacity(1, sizeof(symtab));

    debugger_get_symtab(real_path, s_syms);

    // int char_max = 0;
    // for (size_t i = 0; i < s_syms->len; i++) {
    //     symtab* s_sym = (symtab*)vec_peek(s_syms, i);
    //     if (ELF64_ST_TYPE(s_sym->st_info) == STT_OBJECT && strlen(s_sym->name) > char_max) char_max = strlen(s_sym->name);
    // }

    printf("%s%s% 50s%s%s     %s  %s      %s% 12s%s%s    %s%s\n\n", BOLD, CYAN, "Name", NORMAL, BOLD, "  Scope  ", "Visibility", YELLOW, "Address", NORMAL, BOLD, "Var size", NORMAL);

    for (size_t i = 0; i < s_syms->len; i++) {
        symtab* s_sym = (symtab*)vec_peek(s_syms, i);

        if (ELF64_ST_TYPE(s_sym->st_info) == STT_OBJECT) {
            printf("%s% 50s%s    %s% 8s%s     %s% 9s      %s0x%010lx%s",
                LIGHTCYAN, s_sym->name, NORMAL,
                (ELF64_ST_BIND(s_sym->st_info) == STB_GLOBAL) ? GREEN : NORMAL, s_sym->scope + 4, NORMAL,
                (ELF64_ST_VISIBILITY(s_sym->st_other) != STV_DEFAULT) ? RED : NORMAL, s_sym->visibility + 4,
                YELLOW, s_sym->st_value, NORMAL);
            if (s_sym->st_size != 0) printf("	  %ld\n", s_sym->st_size);
            else printf("\n");
        }
    }
}


void debugger_print_libraries(config_t* cfg)
{
    char real_path[BUFFER_LEN];
    debugger_get_real_path(cfg, real_path);
    UDB_error((real_path != NULL), "Cannot retrieve program's path");

    vec_t* libraries = vec_with_capacity(1, sizeof(library));
    
    debugger_get_libraries(real_path, libraries);

    UDB_user_assert(libraries->len != 0, "It seems that there are no library");

    printf("\t%s%s     Address             %s%sType    %sName%s\n\n", BOLD, YELLOW, NORMAL, BOLD, LIGHTCYAN, NORMAL);
    for (size_t i = 0; i < libraries->len; i++) {
        library* lib = (library*)vec_peek(libraries, i);
        if (lib->type == DT_NEEDED)
            printf("\t%s0x%010lx  %s% 15s    %s%s\n", YELLOW, lib->addr, GREEN, lib->strtype, LIGHTCYAN, lib->name, NORMAL);
        else
            printf("\t%s0x%010lx  %s% 15s\n", YELLOW, lib->addr, NORMAL, lib->strtype);

        // printf("\t%s0x%05llx    %s% 6lld    %s%s%s\n", YELLOW, dst->offset, NORMAL, dst->len, LIGHTCYAN, dst->str, NORMAL);
    }
}

void debugger_print_shared_libraries(config_t* cfg)
{
    char real_path[BUFFER_LEN];
    debugger_get_real_path(cfg, real_path);
    UDB_error((real_path != NULL), "Cannot retrieve program's path");

    vec_t* libraries = vec_with_capacity(1, sizeof(library));

    debugger_get_libraries(real_path, libraries);

    UDB_user_assert(libraries->len != 0, "It seems that there are no library");

    printf("\t%s%s     Address             %s%sType    %sName%s\n\n", BOLD, YELLOW, NORMAL, BOLD, LIGHTCYAN, NORMAL);
    for (size_t i = 0; i < libraries->len; i++) {
        library* lib = (library*)vec_peek(libraries, i);
        if (lib->type == DT_NEEDED)
            printf("\t%s0x%010lx  %s% 15s    %s%s\n", YELLOW, lib->addr, GREEN, lib->strtype, LIGHTCYAN, lib->name, NORMAL);
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
        UDB_error(!(ret == DW_DLV_NO_ENTRY), "This executable does not contains debug info");
        UDB_error(!(ret == DW_DLV_ERROR), dwarf_errmsg(*err));
    }
    return 0;
}

void debugger_print_debug_strings(config_t* cfg)
{
    char real_path[150];
    debugger_get_real_path(cfg, real_path);
    UDB_error((real_path != NULL), "Cannot retrieve program's path");

    vec_t* dstr = vec_with_capacity(1, sizeof(debug_str));

    dwarf_dbg ddbg;
    ddbg.errhand = 0;
    ddbg.tpathlen = FILENAME_MAX;
    ddbg.errarg = 0;
    ddbg.error = 0;
    ddbg.dbg = 0;
    ddbg.groupnumber = DW_GROUPNUMBER_ANY;
    int res = 0;

    res = dwarf_init_path(real_path, ddbg.true_pathbuf, ddbg.tpathlen, ddbg.groupnumber, ddbg.errhand, ddbg.errarg, &ddbg.dbg, &ddbg.error);

    if (res == DW_DLV_ERROR) dwarf_dealloc_error(ddbg.dbg, ddbg.error);
    UDB_error(!(res == DW_DLV_ERROR), dwarf_errmsg(ddbg.error));

    UDB_error(!(res == DW_DLV_NO_ENTRY), "This executable does not contain any debug info");

    get_debug_strings(ddbg.dbg, &ddbg.error, dstr);

    printf("\t%s%sAddress         %s%sSize    %sName%s\n\n", BOLD, YELLOW, NORMAL, BOLD, LIGHTCYAN, NORMAL);
    for (size_t i = 0; i < dstr->len; i++) {
        debug_str* dst = (debug_str*)vec_peek(dstr, i);
        printf("\t%s0x%08llx    %s% 6lld    %s%s%s\n", YELLOW, dst->offset, NORMAL, dst->len, LIGHTCYAN, dst->str, NORMAL);
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

int debugger_get_mem_maps(vec_t* p_mmaps, int inferior_pid)
{
    char path[BUFFER_LEN];
    snprintf(path, sizeof(path), "/proc/%u/maps", inferior_pid);
    FILE* fp = fopen(path, "r");
    UDB_assert(fp, "Failed to read memory maps");

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
    UDB_user_error(cfg->state != DBG_LOADED, "no target executable is currently running.");

    vec_t* p_mmaps = vec_with_capacity(1, sizeof(p_mem_maps));

    debugger_get_mem_maps(p_mmaps, cfg->pid);

    printf("\t%s%s          Addresses begin-end    %s%sPerms   Offset      Device   Inode \t     %sPathname%s\n\n", BOLD, YELLOW, NORMAL, BOLD, CYAN, NORMAL);

    for (size_t i = 0; i < p_mmaps->len; i++) {
        p_mem_maps* map = (p_mem_maps*)vec_peek(p_mmaps, i);
        // printf("%s\n", map->line);
        printf("%s0x%016lx%s-%s0x%016lx    %s%s%s%s%s    %08ld  % 5d:%d    %08d\t     %s%s%s\n",
                YELLOW, map->start, NORMAL, YELLOW, map->end,
                NORMAL, map->perm & 0x4 ? "r" : "-", map->perm & 0x2 ? "w" : "-",
                map->perm & 0x1 ? "\033[31mx\033[0m" : "-", map->shared == true ? "s" : "p",
                map->offset, map->device.major, map->device.minor,
                map->inode, CYAN, map->path, NORMAL);
    }
}

void debugger_get_real_path(config_t* cfg, char* real_path)
{
    if (cfg->state == DBG_LOADED) {
        struct stat buffer;
        int exist = stat(cfg->path, &buffer);
        UDB_user_error((exist == 0), "Executable does not exists");
        // real_path = cfg->path;
        strcpy(real_path, cfg->path);
    }
    else if (cfg->state == DBG_RUNNING){
        char proc_addr[BUFFER_LEN];
        sprintf(proc_addr, "/proc/%d/exe", cfg->pid);
        ssize_t ret = readlink(proc_addr, real_path, BUFFER_LEN);
        UDB_assert(ret >= 0, "failed to read real path");
    }
    else real_path = NULL;
}

void debugger_print_real_path(config_t* cfg)
{
    char real_path[BUFFER_LEN];
    // Verification is made in debugger_get_real_path
    debugger_get_real_path(cfg, real_path);
    UDB_error((real_path != NULL), "Cannot retrieve program's path");

    if (cfg->state != DBG_RUNNING){
        printf("Executable path: %s%s%s.\n", BOLD, real_path, NORMAL);
        printf("In order to get the executable real path, please run the execution using `r` or `run`.\n");
    }
    else printf("Real path: %s%s%s.\n", BOLD, real_path, NORMAL);
}

ssize_t debugger_kill(config_t* cfg, i32 const signal)
{
    UDB_user_error(cfg->state == DBG_RUNNING, "no target executable is currently running.");

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
