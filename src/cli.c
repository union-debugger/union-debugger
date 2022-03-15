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

config_t* parse_args(int const argc, char* const* argv)
{
    struct option const long_options[] = {
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

void completions(char const* buf, linenoiseCompletions* lc)
{
    switch (buf[0]) {
        case 'r':
            linenoiseAddCompletion(lc, "run");
            break;
        case 't':
            linenoiseAddCompletion(lc, "target");
            break;
        case 'a':
            linenoiseAddCompletion(lc, "args");
            break;
        case 'i':
            linenoiseAddCompletion(lc, "info");
            break;
        case 'h':
            linenoiseAddCompletion(lc, "help");
            break;
        case 'q':
            linenoiseAddCompletion(lc, "quit");
            break;
        default:
            return;
    }
}

ssize_t handle_command(char* cmd, config_t* cfg)
{
    size_t flag = 0;

    char* command = malloc(strlen(cmd) + 1);
    command = strcpy(command, cmd);
    char* arguments = NULL;

    // Case where command has arguments
    if (strchr(command, ' ')) {
        char *tmp = malloc(strlen(cmd) + 1);
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
        i32 exec = exec_inferior(config_target(cfg), config_args(cfg));
        if (exec == 0) {
            flag = 0;
        }
    } else if (!strcmp(command, "t") || !strcmp(command, "target")) {
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
    } else if (!strcmp(command, "a") || !strcmp(command, "args")) {
        flag = 1;
        config_set_args(cfg, arguments);
    } else if (!strcmp(command, "i") || !strcmp(command, "info")) {
        flag = 1;
        config_print(cfg);
    } else if (!strcmp(command, "h") || !strcmp(command, "help")) {
        flag = 1;
        printf("Available commands:\n");
        printf("    %srun,    r%s\t -- Launch the executable in the debugger.\n", BOLD, NORMAL);
        printf("    %starget, t%s\t -- Add the argument as the target executable.\n", BOLD, NORMAL);
        printf("    %sargs,   a%s\t -- Add the arguments as arguments of the executable.\n", BOLD, NORMAL);
        printf("    %sinfo,   i%s\t -- Print information about the current debugger configuration.\n", BOLD, NORMAL);
        printf("    %shelp,   h%s\t -- Print the available debugger commands.\n", BOLD, NORMAL);
        printf("    %squit,   q%s\t -- Quit the debugger.\n", BOLD, NORMAL);
    } else if (!strcmp(command, "q") || !strcmp(command, "quit")) {
        flag = 0;
        printf("\nBye :)\n");
    } else {
        flag = 1;
        printf("%s%serror:%s `%s` is an unknow command\n", BOLD, RED, NORMAL, command);
        printf("Type `h` or `help` to display available commands\n");
    }

exit:
    // free(command);
    // free(arguments);
    return flag;
}
