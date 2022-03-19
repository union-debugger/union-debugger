#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../ext/linenoise.h"
#include "../include/cli.h"
#include "../include/consts.h"
#include "../include/debugger.h"
#include "../include/utils.h"

#define no_argument 0
#define required_argument 1 
#define optional_argument 2

config_t* parse_args(int const argc, char* const* argv) {
    struct option const long_options [] = {
        { "path",    required_argument, 0, 'p' },
        { "args",    required_argument, 0, 'a' },
        { "version", no_argument,       0, 'v' },
        { "help",    no_argument,       0, 'h' },
        { 0, 0, 0, 0 },
    };

    config_t* cfg = config_new(NULL);
    UD_assert(cfg, "failed to create config");

    i32 current;
    do {
        i32 option_idx;
        current = getopt_long(argc, argv, "p:vh", long_options, &option_idx);
        switch (current) {
        case 'p':
            config_load(cfg, optarg);
            break;
        case 'h':
            help();
            config_drop(cfg);
            exit(EXIT_SUCCESS);
        case 'v':
            printf("udb v0.1.0\n");
            config_drop(cfg);
            exit(EXIT_SUCCESS);
        default:
            break;
        }
    } while (current != -1);

    return cfg;
}

void completions(char const* buf, linenoiseCompletions* lc) {
    switch (buf[0]) {
    case 'r':
        linenoiseAddCompletion(lc, "run ");
        break;
    case 'c':
        linenoiseAddCompletion(lc, "cont ");
        break;
    case 'l':
        linenoiseAddCompletion(lc, "load ");
        break;
    case 'i':
        linenoiseAddCompletion(lc, "info ");
        break;
    case 'h':
        linenoiseAddCompletion(lc, "help ");
        break;
    case 'q':
        linenoiseAddCompletion(lc, "quit ");
        break;
    case 'mm':
        linenoiseAddCompletion(lc, "mmaps ");
        break;
    case 'm':
        linenoiseAddCompletion(lc, "memory ");
        break;
    case 'R':
        linenoiseAddCompletion(lc, "registers ");
        break;
    case 'k':
        linenoiseAddCompletion(lc, "kill ");
        break;
    default:
        return;
    }
}

bool handle_command(char* prompt, config_t* cfg)
{
    char* cmd = strtok(prompt, " "); 
    if (!cmd) {
        return true;
    }

    if (!strcmp(cmd, "r") || !strcmp(cmd, "run")) {
        if (!cfg->target) {
            printf("%s%serror:%s no executable has been defined yet\n", BOLD, RED, NORMAL);
            return true;
        }
        if (access(cfg->target, F_OK) != 0 || access(cfg->target, X_OK != 0)) {
            printf("%s%serror:%s executable does not exist or has not the required permissions\n",
                   BOLD, RED, NORMAL);
            return true;
        }

        char* argv[MAX_ARGS + 1];
        for (size_t i = 0; i < MAX_ARGS; i++) {
            argv[i] = strtok(NULL, " ");
            if (argv[i] == NULL) {
                break;
            }
        }
        argv[MAX_ARGS] = NULL;

        debug_run(cfg, (char* const*)argv);
        return true;
    } else if (!strcmp(cmd, "c") || !strcmp(cmd, "cont")) {
        debug_capture_signal(cfg);
        return true;
    } else if (!strcmp(cmd, "l") || !strcmp(cmd, "load")) {
        char* target = strtok(NULL, " ");
        if (!target) {
            printf("%s%serror:%s command `target` takes at least one argument\n", BOLD, RED, NORMAL);
            return true;
        }
        if (substr_cnt(target, " ") > 1) {
            printf("%s%swarning:%s command `target` only takes one argument\n", BOLD, YELLOW, NORMAL);
            return true;
        }
        config_load(cfg, target);
        return true;
    } else if (!strcmp(cmd, "i") || !strcmp(cmd, "info")) {
        config_print(cfg);
        return true;
    } else if (!strcmp(cmd, "h") || !strcmp(cmd, "help")) {
        printf("%sAvailable commands:%s\n", BOLD, NORMAL);
        printf("\n  Program configuration:\n");
        printf("    %srun,       r%s\t -- Launch the executable in the debugger.\n", BOLD, NORMAL);
        printf("    %starget,    t%s\t -- Add the argument as the target executable.\n", BOLD, NORMAL);
        printf("    %sinfo,      i%s\t -- Print information about the current debugger configuration.\n", BOLD, NORMAL);
        printf("    %shelp,      h%s\t -- Print the available debugger cmds.\n", BOLD, NORMAL);
        printf("    %squit,      q%s\t -- Quit the debugger.\n", BOLD, NORMAL);
        printf("\n  Debugging options:\n");
        printf("    %smemory,    m%s\t -- Print memory usage status.\n", BOLD, NORMAL);
        printf("    %smmaps,    mm%s\t -- Print memory maps.\n", BOLD, NORMAL);
        printf("    %sregisters, R%s\t -- Print registers status.\n", BOLD, NORMAL);
        printf("    %skill,      k%s\t -- Sends a signal to child process. Sends a SIGKILL signal by default.\n", BOLD, NORMAL);
        return true;
    } else if (!strcmp(cmd, "q") || !strcmp(cmd, "quit")) {
        printf("\nBye :)\n");
        return false;
    } else if (!strcmp(cmd, "R") || !strcmp(cmd, "registers")) {
        debug_print_regs(cfg);
        return true;
    } else if (!strcmp(cmd, "m") || !strcmp(cmd, "memory")) {
        debug_print_mem();
        return true;
    } else if (!strcmp(cmd, "mm") || !strcmp(cmd, "mmaps")) {
        debug_print_mem_maps(cfg->inferior_pid);
        return true;
    } else if (!strcmp(cmd, "k") || !strcmp(cmd, "kill")) {
        printf("debug : %d\n", cfg->inferior_pid);
        i32 res = debug_kill(cfg, "");
        printf("kill res %d\n", res);
        return true;
    } else if (!strcmp(cmd, "pids")) {
        debug_print_pids();
        return true;
    } else if (!strcmp(cmd, "childpid")) {
        debug_print_child_pids(cfg);
        return true;
    } else if (!strcmp(cmd, "path")) {
        debug_print_real_path(cfg);
        return true;
    } else {
        printf("%s%serror:%s `%s` is an unknow cmd\n", BOLD, RED, NORMAL, cmd);
        printf("Type `h` or `help` to display available cmds\n");
        return true;
    }
}
