#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/debugger.h"
#include "../include/utils.h"

i32 exec_inferior(char const* path, char* const* args)
{
    pid_t inferior = fork();

    i32 status = 0;
    if (inferior == 0) {
        ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
        status = execvp(path, args);
    } else {
        printf("Process %d launched.\n", inferior);
        dbg_inferior(inferior);
        printf("Process %d exited.\n", inferior);
    }

    return status;
}

void dbg_inferior(pid_t inferior)
{
    while (1) {
        i32 wait_status;
        i32 options = 0;
        waitpid(inferior, &wait_status, options);

        if (WIFSTOPPED(wait_status)) {
            printf("Inferior has stopped. Resuming...\n");
            ptrace(PTRACE_CONT, inferior, NULL, NULL);
        } else if (WIFEXITED(wait_status)) {
            printf("Inferior has finished executing. Terminating...\n");
            return;
        }
    }
}
