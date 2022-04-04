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


typedef struct {
    unsigned int st_name;
    char* name;
    unsigned char st_info;
    char* scope;
    char* type;
    unsigned char st_other;
    char* visibility;
    unsigned long int st_value;
    unsigned long int st_size;
} symtab;


const char* syscall_tab[330] = { "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield",
    "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
    "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname",
    "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop",
    "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
    "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown",
    "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid",
    "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid",
    "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
    "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority",
    "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
    "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl",
    "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname",
    "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg",
    "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
    "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity",
    "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create",
    "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create",
    "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep",
    "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink",
    "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl",
    "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat",
    "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat",
    "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice",
    "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
    "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv",
    "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
    "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
    "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create",
    "kexec_file_load", "bpf", "stub_execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2", "pwritev2", NULL };

ssize_t debugger_run(config_t* cfg, char* const* argv);
ssize_t debugger_wait_signal(config_t* cfg);
ssize_t debugger_cont(config_t* cfg);
ssize_t debugger_kill(config_t* cfg, i32 const signal);
void debugger_print_regs(config_t* cfg);
void debugger_print_mem();
void debugger_pids(config_t* cfg);
void debugger_get_real_path(config_t* cfg, char* real_path);
void debugger_print_real_path(config_t* cfg);
void debugger_print_mem_maps(config_t* cfg);
void debugger_backtrace(int dbg_state);
void debugger_print_debug_strings(config_t* cfg);
void debugger_print_libraries(config_t* cfg);
void debugger_print_shared_libraries(config_t* cfg);
void debugger_print_global_vars(config_t* cfg);
void debugger_print_symtab(config_t* cfg);
void debugger_print_functions(config_t* cfg);
void debugger_print_variables(config_t* cfg);