#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/personality.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <wait.h>

#include <libunwind.h>
// #include <libunwind-x86_64.h>
#include <libunwind-ptrace.h>
#include <endian.h>

#include "../include/breakpoint.h"
#include "../include/debugger.h"
#include "../include/utils.h"
#include "../include/types.h"
#include "../include/config.h"
#include "../ext/vec.h"

ssize_t debugger_run(config_t *cfg, char* const* argv)
{
    if (cfg->state == STATE_UNINIT) {
        printf("%sinfo:%s debugger is uninitialized\n", MAGENTA, NORMAL);
        return -1;
    }

    // if (cfg->state == STATE_RUNNING) {
    //     printf("Inferior process %d is currently being debugged.", cfg->pid);
    //     printf("Are you sure you want to restart? [y/n] ");
    //     char ans[BUFFER_LEN];
    //     scanf("%s", ans);
    //     if (ans[0] == 'y' || ans[0] == 'Y') {
    //         i32 ret = debugger_kill(cfg, SIGKILL);
    //         UDB_assert(ret <= 0, "failed to kill child process");
    //     } else if (ans[0] == 'n' || ans[0] == 'N') {
    //         printf("Continuing debugging session\n");
    //         return true;
    //     } else {
    //         printf("\n%s%serror:%s `%s` is not a valid answer\n", BOLD, RED, NORMAL, ans);
    //         return true;
    //     }
    // }

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
        config_print(cfg);
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

restart:
    if (waitpid(cfg->pid, &wstatus, 0) < 0) {
        return -1;
    }

    if (WIFEXITED(wstatus)) {
        printf("Inferior process %d terminated normally (code %d).\n", cfg->pid, WEXITSTATUS(wstatus));
        cfg->state = STATE_INIT;
    } else if (WIFSIGNALED(wstatus)) {
        siginfo_t siginfo;
        if (ptrace(PTRACE_GETSIGINFO, cfg->pid, NULL, &siginfo) < 0 && errno == EINVAL) {
            goto restart;
        }
        printf("Inferior process %d stopped at address %p\n",
               cfg->pid, siginfo.si_addr);
        i32 signal = WTERMSIG(wstatus);
        printf("Inferior process %d terminated with signal SIG%s: %s\n",
               cfg->pid,
               sigabbrev_np(signal),
               sigdescr_np(signal));
        cfg->state = STATE_INIT;
    } else if (WIFSTOPPED(wstatus)) {
        i32 stopsig = WSTOPSIG(wstatus);
        if (stopsig == SIGTRAP) {
            // Breakpoint and execvp
            struct user_regs_struct registers;
            if (ptrace(PTRACE_GETREGS, cfg->pid, NULL, &registers) < 0) {
                return -1;
            }

            u64 address = registers.rip - 1;
            breakpoint_t* b = breakpoint_peek(cfg->breakpoints, address);
            if (b) {
                printf("Stopped at breakpoint (address: 0x%zx)\n", b->address);
            } else {
                // debugger_cont(cfg);
            }
        } else {
            if (stopsig == SIGSTOP || stopsig == SIGTSTP || stopsig == SIGTTIN || stopsig == SIGTTOU) {
                siginfo_t siginfo;
                if (ptrace(PTRACE_GETSIGINFO, cfg->pid, NULL, &siginfo) < 0 && errno == EINVAL) {
                    goto restart;
                }
            }
            ptrace(PTRACE_CONT, cfg->pid, NULL, stopsig);
            goto restart;
        }
    } else {
        return -1;
    }

    return wstatus;
}

ssize_t debugger_cont(config_t* cfg)
{
    if (cfg->state != STATE_RUNNING) {
        printf("%sinfo:%s debugger is not running\n", MAGENTA, NORMAL);
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
    printf("Child PID:\t%d\n", cfg->pid);
    printf("Child PPID:\t%d\n", getpid());
}

void debugger_get_regs(pid_t pid, struct user_regs_struct* regs)
{
    i32 ret = ptrace(PTRACE_GETREGS, pid, 0, regs);
    UDB_assert(ret >= 0, "could not get registers");
}

void debugger_print_regs(config_t* cfg)
{
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
    printf("Current real memory: %d\n", mem.real_mem_curr);
    printf("Current virtual memory: %d\n", mem.virt_mem_curr);
    printf("Peak real memory: %d\n", mem.real_mem_peak);
    printf("Peak virtual memory: %d\n", mem.virt_mem_peak);
}


/*
* DEBUGGER BACKTRACE
* using libunwind
*/

void debugger_backtrace(pid_t child) {
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
        perror("ptrace child");
    }

    unw_addr_space_t space = unw_create_addr_space(&_UPT_accessors, __LITTLE_ENDIAN);
    void* target = _UPT_create(child);

    unw_word_t ip, sp;
    char funcname[128];
    unw_word_t offset;
    unw_cursor_t cursor;
    unw_init_remote(&cursor, space, target);

    while (unw_step(&cursor) > 0) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        unw_get_proc_name(&cursor, funcname, sizeof(funcname), &offset);

        printf("ip = %lx, sp = %lx %s(+%lu)\n", (long)ip, (long)sp, funcname, offset);
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
void debugger_get_mem_maps(vec_t* p_mmaps, int inferior_pid)
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

        strcpy(map.path, buff_path);

        VEC_MUT(p_mmaps, p_mem_maps, p_mmaps->capacity-1, map);
        int ret = vec_resize(p_mmaps, p_mmaps->capacity+1);
        nm++;
    }
    fclose(fp);
}


void debugger_print_mem_maps(config_t* cfg)
{
    vec_t* p_mmaps = vec_with_capacity(1, sizeof(p_mem_maps));

    UDB_user_assert(cfg->state == STATE_RUNNING, "Tracee must be running to run that command.");

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

void debugger_print_real_path(config_t* cfg) {
    char real_path[BUFFER_LEN];
    debugger_get_real_path(cfg->pid, real_path);
    printf("Real path: %s\n", real_path);
}

ssize_t debugger_kill(config_t* cfg, i32 const signal)
{
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
    cfg->state = STATE_INIT;

    // Zombie Child Assertion
    ret = waitpid(cfg->pid, NULL, WNOHANG);
    kill(getpid(), SIGCHLD);
    UDB_assert(ret >= 0, "child process is a zombie");

    return ret;
}
