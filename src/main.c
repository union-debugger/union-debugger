#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void dbg_tracee(pid_t tracee)
{
    while (1) {
        int status;
        waitpid(tracee, &status, 0);

        if (WIFSTOPPED(status)) {
            fprintf(stderr, "Tracee has stopped. Resuming...\n");
            ptrace(PTRACE_CONT, tracee, NULL, NULL);
        } else if (WIFEXITED(status)) {
            fprintf(stderr, "Tracee has finished executing. Terminating...\n");
            exit(0);
        }
    }
}

void exec_tracee(const char *path, char **const argv)
{
    pid_t tracee = fork();

    if (tracee == 0) {
        ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
        execv(path, argv + 1);
    } else {
        dbg_tracee(tracee);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return fprintf(stderr, "Usage: %s PATH [OPTIONS]\n", argv[0]), 1;

    exec_tracee(argv[1], argv);

    return 0;
}
