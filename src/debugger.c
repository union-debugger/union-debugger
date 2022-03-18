#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include <sys/user.h>

#include "../include/debugger.h"
#include "../include/utils.h"
#include "../include/types.h"
#include "../include/config.h"

i32 debug_run(config_t *cfg){
    i32 status = 0;

    pid_t inferior_pid = fork();
    cfg->inferior_pid = inferior_pid;

    if (inferior_pid == 0){
        ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
        debug_print_pids();
        status = execvp(cfg->target, cfg->args);
        printf("Done exec !\n");
        return status;
    }
    else {
        printf("Child %d started with %s %s\n", inferior_pid, cfg->target, (cfg->args == NULL) ? "" : (char*)cfg->args);
        debug_print_pids();
        UD_assert(inferior_pid, "Fork failed");
    }
    return status;
}

void debug_capture_signal(pid_t inferior_pid){
    i32 wait_status;
    i32 options = 0;
    waitpid(inferior_pid, &wait_status, options);

    if (WIFSTOPPED(wait_status)) {
        printf("Inferior has stopped. Resuming...\n");
        ptrace(PTRACE_CONT, inferior_pid, NULL, NULL);
    } else if (WIFEXITED(wait_status)) {
        printf("Inferior has finished executing. Terminating...\n");
        return;
    }
}

void debug_print_pids(){
    pid_t pid = getpid();
    pid_t ppid = getppid();
    printf("pid : \t%d\n", pid);
    printf("ppid : \t%d\n",ppid);
}

void debug_print_child_pids(config_t* cfg) {
    printf("Child pid : \t%d\n", cfg->inferior_pid);
    printf("Child ppid : \t%d\n", getpid());
}


void debug_get_regs(i8 child, struct user_regs_struct *regs) {
    i8 res = 0;
    res = ptrace(PTRACE_GETREGS, child, 0, regs);
    UD_assert((res != 0), "Cannot PTRACE_GETREGS");
}

void debug_print_regs(config_t *cfg){
    // REGISTERS
    struct user_regs_struct regs;
    debug_get_regs(cfg->inferior_pid, &regs);
    // i8 res = ptrace(PTRACE_GETREGS, child, 0, regs);
    // UD_assert(!res, "Cannot PTRACE_GETREGS");

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


// i32 needed
void debug_get_real_path(char real_path[], i32 path_size){
    readlink("/proc/self/exe", real_path, path_size);
}

void debug_print_real_path(){
    i32 path_size = 300;
    char real_path[path_size];
    debug_get_real_path(real_path, path_size);
    printf("Real Path : %s\n", real_path);
}



i8 debug_kill(config_t* cfg, char const* arguments) {

    char **args = strsplit(arguments, " ");

    // int nb_args = substr_cnt(arguments, " ");
    // printf("%d ARGS !\n", nb_args);
    // for (int i = 0; i < nb_args; i++)
    //     printf("%d : %s\n", i, args[i]);

    UD_assert(cfg && args, "invalid parameter (null pointer)");
    i8 signal = 0;

    signal = atoi(args[0]);
    printf("KILL %d\n", signal);

    i8 res;
    if ((res = kill(cfg->inferior_pid, signal)) != 0)
        printf("Killing (%d) %d failed\n", res, cfg->inferior_pid);

    // Zombie Child Assertion
    UD_assert((res = waitpid(cfg->inferior_pid, NULL, WNOHANG) != 0), "Child is zombie");
    return res;
}