#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
// #include <asm/siginfo.h>

#include "../include/breakpoint.h"
#include "../include/debugger.h"
#include "../include/utils.h"
#include "../include/types.h"
#include "../include/config.h"

i32 debugger_run(config_t *cfg, char* const* argv)
{
    if (cfg->state == STATE_UNINIT) {
        printf("%sinfo:%s debugger is not loaded\n", MAGENTA, NORMAL);
    }

    i32 status = 0;
    char* path = cfg->target;
    char* args[MAX_ARGS + 2];
    args[0] = path;
    memcpy(&args[1], argv, MAX_ARGS * sizeof(char*));
    args[MAX_ARGS + 1] = NULL;

    pid_t inferior_pid = fork();
    if (inferior_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        personality(ADDR_NO_RANDOMIZE);
        execvp(cfg->target, args);
        printf("Failed to execute inferior: %s\n", strerror(errno));
        abort();
    } else if (inferior_pid > 0) {
        cfg->inferior_pid = inferior_pid;
        config_print(cfg);
        status = debugger_wait_signal(cfg);
        if (ptrace(PTRACE_SETOPTIONS, cfg->inferior_pid, NULL, PTRACE_O_EXITKILL) < 0) {
            return -1;
        }
    } else {
        UDB_assert(false, "fork failed");
    }

    return status;
}

i32 debugger_wait_signal(config_t* cfg)
{
    i32 wstatus;

restart:
    if (waitpid(cfg->inferior_pid, &wstatus, 0) < 0) {
        return -1;
    }

    if (WIFEXITED(wstatus)) {
        printf("Inferior process #%d terminated normally (code %d)\n", cfg->inferior_pid, WEXITSTATUS(wstatus));
    } else if (WIFSIGNALED(wstatus)) {
        siginfo_t siginfo;
        if (ptrace(PTRACE_GETSIGINFO, cfg->inferior_pid, NULL, &siginfo) < 0 && errno == EINVAL) {
            goto restart;
        }
        printf("Inferior process #%d stopped at address %p\n",
               cfg->inferior_pid, siginfo.si_addr);
        i32 signal = WTERMSIG(wstatus);
        printf("Inferior process #%d terminated.\nReceived signal SIG%s: %s\n",
               cfg->inferior_pid,
               sigabbrev_np(signal),
               sigdescr_np(signal));
    } else if (WIFSTOPPED(wstatus)) {
        i32 stopsig = WSTOPSIG(wstatus);
        if (stopsig == SIGTRAP) {
            // Breakpoint and execvp
            struct user_regs_struct registers;
            if (ptrace(PTRACE_GETREGS, cfg->inferior_pid, NULL, &registers) < 0) {
                return -1;
            }

            u64 address = registers.rip - 1;
            breakpoint_t* b = breakpoint_peek(cfg->breakpoints, address);
            if (b) {
                printf("Stopped at breakpoint (address: %zx)\n", b->address);
            } else {
                // debug_cont(cfg);
            }
        } else {
            if (stopsig == SIGSTOP || stopsig == SIGTSTP || stopsig == SIGTTIN || stopsig == SIGTTOU) {
                siginfo_t siginfo;
                if (ptrace(PTRACE_GETSIGINFO, cfg->inferior_pid, NULL, &siginfo) < 0 && errno == EINVAL) {
                    goto restart;
                }
            }
            ptrace(PTRACE_CONT, cfg->inferior_pid, NULL, stopsig);
            goto restart;
        }
    } else {
        return -1;
    }

    return wstatus;
}

i32 debug_cont(config_t* cfg)
{
    if (cfg->state != STATE_RUNNING) {
        printf("%sinfo:%s debugger is not running\n", MAGENTA, NORMAL);
        return -1;
    }

    if (breakpoint_step(cfg) < 0) {
        printf("%s%serror:%s failed to step\n", BOLD, RED, NORMAL);
        return -1;
    }

    if (ptrace(PTRACE_CONT, cfg->inferior_pid, NULL, NULL) < 0) {
        printf("%s%serror:%s failed to continue\n", BOLD, RED, NORMAL);
        return -1;
    }

    debugger_wait_signal(cfg);
    return 0;
}

void debug_print_pids() {
    pid_t pid = getpid();
    pid_t ppid = getppid();
    printf("pid: \t%d\n", pid);
    printf("ppid: \t%d\n", ppid);
}

void debug_print_child_pids(config_t* cfg) {
    printf("Child pid: \t%d\n", cfg->inferior_pid);
    printf("Child ppid: \t%d\n", getpid());
}

void debug_get_regs(i8 child, struct user_regs_struct *regs) {
    i8 res = 0;
    res = ptrace(PTRACE_GETREGS, child, 0, regs);
    UDB_assert((res != 0), "Cannot PTRACE_GETREGS");
}

void debug_print_regs(config_t *cfg) {
    // REGISTERS
    struct user_regs_struct regs;
    debug_get_regs(cfg->inferior_pid, &regs);
    // i8 res = ptrace(PTRACE_GETREGS, child, 0, regs);
    // UDB_assert(!res, "Cannot PTRACE_GETREGS");

    printf("Child r15 \t : %lld\n", regs.r15);
    printf("Child r14 \t : %lld\n", regs.r14);
    printf("Child r13 \t : %lld\n", regs.r13);
    printf("Child r12 \t : %lld\n", regs.r12);
    printf("Child rbp \t : %lld\n", regs.rbp);
    printf("Child rbx \t : %lld\n", regs.rbx);
    printf("Child r11 \t : %lld\n", regs.r11);
    printf("Child r10 \t : %lld\n", regs.r10);
    printf("Child r9 \t : %lld\n", regs.r9);
    printf("Child r8 \t : %lld\n", regs.r8);
    printf("Child rax \t : %lld\n", regs.rax);
    printf("Child rcx \t : %lld\n", regs.rcx);
    printf("Child rdx \t : %lld\n", regs.rdx);
    printf("Child rsi \t : %lld\n", regs.rsi);
    printf("Child rdi \t : %lld\n", regs.rdi);
    printf("Child orig_rax \t : %lld\n", regs.orig_rax); // Last system call
    printf("Child rip \t : %lld\n", regs.rip);
    printf("Child cs \t : %lld\n", regs.cs);
    printf("Child eflags \t : %lld\n", regs.eflags);
    printf("Child rsp \t : %lld\n", regs.rsp);
    printf("Child ss \t : %lld\n", regs.ss);
    printf("Child fs_base \t : %lld\n", regs.fs_base);
    printf("Child gs_base \t : %lld\n", regs.gs_base);
    printf("Child ds \t : %lld\n", regs.ds);
    printf("Child es \t : %lld\n", regs.es);
    printf("Child fs \t : %lld\n", regs.fs);
    printf("Child gs \t : %lld\n", regs.gs);
}

void debug_get_mem(p_mem* mem){
    char buffer[1024] = "";

    FILE* fp_status = fopen("/proc/self/status", "r");

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

void debug_print_mem(){
    p_mem mem;
    debug_get_mem(&mem);

    printf("currRealMem : %d\n", mem.real_mem_curr);
    printf("peakRealMem : %d\n", mem.real_mem_peak);
    printf("currVirtMem : %d\n", mem.virt_mem_curr);
    printf("peakVirtMem : %d\n", mem.virt_mem_peak);
}


/*
** Memory Maps
** TODO : transform struct in vec.
** TODO : Linenoise autocompletion failing with `memory`
** TODO : Must verify the child is running before executing the command (verif with cfg else give the debugger a current status and verify it)

// Not able to get maps elsewhere than in the /proc

// start & end of memory address of the contigeous virtual memory
// Permissions : can be [r]ead, [w]rite, e[x]ecuted. If region not [s]hared, it's [p]rivate.
// Segfault occurs if process attemps to access memory in a non expected way.
// Permissions can be changed using the mprotect system call.
// Offset : If memory is mapped from a file, offset is the offset from where to read. If not from a file, it's 0
// [dev]ive in /dev/* represent it's driver ID (major) and a (minor) metadata used by the related driver to identify the block.
// pathname : the file readed, if any. Can also be - [stack] for main thread's stack
//                                                 - [stack:tid] stack for a specific Thread ID
//                                                 - [vdso] virtual dynamically linked shared object. When using standard functions, defined in the C library, they are called from the kernel, which can be very slow. To avoid this, we load the library in the environment of each program using its auxiliary vector. (ELF) (AT_SYSINFO_EHDR tag) // can be shown LD_SHOW_AUXV=1 /bin/true
*/

void debug_get_mem_maps(p_mem_maps* p_mmaps, int inferior_pid) {
    char path[250];
    snprintf(path, sizeof(path), "/proc/%u/maps", inferior_pid);
    FILE* fp = fopen(path, "r");

    // UDB_assert(fp, "Proc Maps open");

    char* buff = NULL;
    size_t buff_size = 0, i = 0;
    while (getline(&buff, &buff_size, fp) != EOF) {
        memcpy(p_mmaps[i].line, strtok(buff, "\n"), 500);
        // printf("%s\n%s\n=====\n", buff, p_mmaps[i].line);
        char* buff_start = strtok(buff, "-");
        char* buff_end = strtok(NULL, " ");
        char* buff_perm = strtok(NULL, " ");
        char* buff_offset = strtok(NULL, " ");
        char* buff_dev_major = strtok(NULL, ":");
        char* buff_dev_minor = strtok(NULL, " ");
        char* buff_inode = strtok(NULL, " ");
        char* buff_path = strtok(NULL, " ");

        // Start, end and size are integers, instead of hexa.
        p_mmaps[i].start = strtoul(buff_start, NULL, 16);
        p_mmaps[i].end = strtoul(buff_end, NULL, 16);
        p_mmaps[i].size = p_mmaps[0].end - p_mmaps[0].start;

        p_mmaps[i].perm = 0;
        if (buff_perm[0] == 'r') p_mmaps[i].perm |= 0x04;
        if (buff_perm[1] == 'w') p_mmaps[i].perm |= 0x02;
        if (buff_perm[2] == 'x') p_mmaps[i].perm |= 0x01;
        p_mmaps[i].shared = buff_perm[3] == 'p' ? false : true;

        // p_mmaps[i].offset = strtoul(buff_offset, NULL, 16);
        p_mmaps[i].offset = atoi(buff_offset);
        p_mmaps[i].device.major = strtoul(buff_dev_major, NULL, 10);
        p_mmaps[i].device.minor = strtoul(buff_dev_minor, NULL, 10);
        p_mmaps[i].inode = atoi(buff_inode);

        strcpy(p_mmaps[i].path, buff_path);
        i++;
    }
    fclose(fp);
}


void debug_print_mem_maps(int inferior_pid) {
    int p_mmaps_size = 20;
    p_mem_maps p_mmaps[p_mmaps_size];
    debug_get_mem_maps(p_mmaps, inferior_pid);
    for (int i = 0; i < p_mmaps_size; i++) {
        // printf("============\n");
        printf("%s\n", p_mmaps[i].line);
        // printf("%ld-%ld %d%s %ld   %d:%d %d \t\t%s\n", p_mmaps[i].start, p_mmaps[i].end, p_mmaps[i].perm, p_mmaps[i].shared == true ? "s" : "p", p_mmaps[i].offset, p_mmaps[i].device.major, p_mmaps[i].device.minor, p_mmaps[i].inode, p_mmaps[i].path);
    }
}



void debug_get_real_path(pid_t inferior_pid, char* real_path) {
    char proc_addr[BUFFER_LEN];
    sprintf(proc_addr, "/proc/%d/exe", inferior_pid);
    readlink(proc_addr, real_path, BUFFER_LEN);
}

void debug_print_real_path(config_t* cfg) {
    char real_path[BUFFER_LEN];
    debug_get_real_path(cfg->inferior_pid, real_path);
    printf("Real Path : %s\n", real_path);
}

i8 debug_kill(config_t* cfg, char const* arguments) {
    // char **args = strsplit(cfg->args, arguments, " ");

    // int nb_args = substr_cnt(arguments, " ");
    // printf("%d ARGS !\n", nb_args);
    // for (int i = 0; i < nb_args; i++)
    //     printf("%d : %s\n", i, args[i]);

    // UDB_assert(cfg && args, "invalid parameter (null pointer)");
    i8 signal = 0;

    // signal = atoi(args[0]);
    printf("KILL %d\n", signal);

    i8 res;
    if ((res = kill(cfg->inferior_pid, signal)) != 0)
        printf("Killing (%d) %d failed\n", res, cfg->inferior_pid);

    // Zombie Child Assertion
    UDB_assert((res = waitpid(cfg->inferior_pid, NULL, WNOHANG) != 0), "Child is zombie");
    return res;
}
