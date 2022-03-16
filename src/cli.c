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

    config_t* cfg = config_new(NULL, NULL, 0);
    UD_assert(cfg, "failed to create config");

    i32 current;
    do {
        i32 option_idx;
        current = getopt_long(argc, argv, "p:a:vh", long_options, &option_idx);
        switch (current) {
        case 'p':
            config_set_target(cfg, optarg);
            break;
        case 'a':
            if (!config_target(cfg)) {
                printf("%s%serror:%s %s\n%s\n\n", BOLD, RED, NORMAL,
                    "the `--args` requires a path to be set", "See the help below");
                help();
                config_drop(cfg);
                exit(EXIT_FAILURE);
            }
            config_set_args(cfg, optarg);
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
    case 't':
        linenoiseAddCompletion(lc, "target ");
        break;
    case 'a':
        linenoiseAddCompletion(lc, "args ");
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
    default:
        return;
    }
}

ssize_t handle_command(char* cmd, config_t* cfg) {
    size_t flag = 0;

    char* command = malloc(strlen(cmd) + 1);
    command = strcpy(command, cmd);
    char* arguments = NULL;

    // Case where command has arguments
    if (strchr(command, ' ')) {
        char* tmp = malloc(strlen(cmd) + 1);
        tmp = strcpy(tmp, cmd);
        UD_assert(tmp, "string copy failed");
        command = strtok(cmd, " ");
        arguments = strtok(tmp + strlen(command) + 1, "\0");
    }

    if (!strcmp(command, "r") || !strcmp(command, "run")) {
        flag = 1;
        if (!config_target(cfg)) {
            printf("%s%serror:%s no executable has been defined yet\n", BOLD, RED, NORMAL);
            goto exit;
        }
        if (!exists(cfg->target)) {
            printf("%s%serror:%s the executable does not exist\n", BOLD, RED, NORMAL);
            goto exit;
        }
        if (!access(cfg->target, X_OK)) {
            printf("%s%serror:%s the executable has not the required permissions\n", BOLD, RED, NORMAL);
            goto exit;
        }
        // i32 exec = exec_inferior(config_target(cfg), config_args(cfg));
        i32 exec_status = debug_run(cfg);
        if (!exec_status) flag = 1;
    }
    else if (!strcmp(command, "t") || !strcmp(command, "target")) {
        flag = 1;
        if (!arguments) {
            printf("%s%serror:%s command `target` takes at least one argument\n", BOLD, RED, NORMAL);
            goto exit;
        }
        if (substr_cnt(arguments, " ") > 1) {
            printf("%s%swarning:%s command `target` only takes one argument\n", BOLD, YELLOW, NORMAL);
        }
        char* target = strtok(arguments, " ");
        config_set_target(cfg, target);
    }
    else if (!strcmp(command, "a") || !strcmp(command, "args")) {
        flag = 1;
        config_set_args(cfg, arguments);
    }
    else if (!strcmp(command, "i") || !strcmp(command, "info")) {
        flag = 1;
        config_print(cfg);
    }
    else if (!strcmp(command, "h") || !strcmp(command, "help")) {
        flag = 1;
        printf("%sAvailable commands:%s\n", BOLD, NORMAL);
        printf("\n  Program configuration:\n");
        printf("    %srun,    r%s\t -- Launch the executable in the debugger.\n", BOLD, NORMAL);
        printf("    %starget, t%s\t -- Add the argument as the target executable.\n", BOLD, NORMAL);
        printf("    %sargs,   a%s\t -- Add the arguments as arguments of the executable.\n", BOLD, NORMAL);
        printf("    %sinfo,   i%s\t -- Print information about the current debugger configuration.\n", BOLD, NORMAL);
        printf("    %shelp,   h%s\t -- Print the available debugger commands.\n", BOLD, NORMAL);
        printf("    %squit,   q%s\t -- Quit the debugger.\n", BOLD, NORMAL);
        printf("\n  Debugging options:\n");
        printf("    %smemory,   mem%s\t -- Print memory usage status.\n", BOLD, NORMAL);
        printf("    %sregisters,   regs%s\t -- Print registers status.\n", BOLD, NORMAL);
        printf("    %skill,   k%s\t -- Sends a signal to child process. Sends a SIGKILL signal by default.\n", BOLD, NORMAL);
    }
    else if (!strcmp(command, "q") || !strcmp(command, "quit")) {
        flag = 0;
        printf("\nBye :)\n");
    }
    else if (!strcmp(command, "regs") || !strcmp(command, "registers")) {
        flag = 1;
        debug_print_regs(cfg);
    }
    else if (!strcmp(command, "mem") || !strcmp(command, "memory")) {
        flag = 1;
        debug_print_mem();
    }
    else if (!strcmp(command, "k") || !strcmp(command, "kill")) {
        flag = 1;
        printf("debug : %d\n", cfg->inferior_pid);
        i32 res = debug_kill(cfg, arguments);
        printf("kill res %d\n", res);
    }
    else if (!strcmp(command, "pids")) {
        flag = 1;
        debug_print_pids();
    }
    else if (!strcmp(command, "childpid")) {
        flag = 1;
        debug_print_child_pids(cfg);
    }
    else if (!strcmp(command, "path")) {
        flag = 1;
        debug_print_real_path();
    }
    else {
        flag = 1;
        printf("%s%serror:%s `%s` is an unknow command\n", BOLD, RED, NORMAL, command);
        printf("Type `h` or `help` to display available commands\n");
    }

exit:
    // free(command);
    // free(arguments);
    return flag;
}
