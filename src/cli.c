#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../ext/linenoise.h"
#include "../include/breakpoint.h"
#include "../include/cli.h"
#include "../include/consts.h"
#include "../include/debugger.h"
#include "../include/utils.h"

#define ENABLE 1
#define DISABLE 0

void completions(char const* buf, linenoiseCompletions* lc)
{
    switch (buf[0]) {
    case 'b':
        linenoiseAddCompletion(lc, "break ");
        linenoiseAddCompletion(lc, "backtrace ");
        break;
    case 'c':
        linenoiseAddCompletion(lc, "cont ");
        break;
    case 'e':
        linenoiseAddCompletion(lc, "enable ");
        break;
    case 'd':
        linenoiseAddCompletion(lc, "disable ");
        linenoiseAddCompletion(lc, "debug_str ");
        break;
    case 'h':
        linenoiseAddCompletion(lc, "help ");
        break;
    case 'i':
        linenoiseAddCompletion(lc, "info ");
        break;
    case 'k':
        linenoiseAddCompletion(lc, "kill ");
        break;
    case 'l':
        linenoiseAddCompletion(lc, "load ");
        linenoiseAddCompletion(lc, "list ");
        linenoiseAddCompletion(lc, "libs ");
        break;
    case 'm':
        linenoiseAddCompletion(lc, "memmaps ");
        linenoiseAddCompletion(lc, "memory ");
        break;
    case 'p':
        linenoiseAddCompletion(lc, "path ");
        linenoiseAddCompletion(lc, "pids ");
        break;
    case 'q':
        linenoiseAddCompletion(lc, "quit ");
        break;
    case 'r':
        linenoiseAddCompletion(lc, "run ");
        linenoiseAddCompletion(lc, "registers ");
        break;
    case 's':
        linenoiseAddCompletion(lc, "shared_libs ");
        linenoiseAddCompletion(lc, "step ");
        break;
    default:
        return;
    }
}

void command_break(config_t* cfg, char* value)
{
    if (cfg->state == STATE_UNINIT) {
        printf("%s%serror:%s debugger has not been initialized yet\n", BOLD, RED, NORMAL);
        return;
    }

    size_t addr = parse_value(value);
    if (addr == SIZE_MAX) {
        printf("%s%serror:%s failed to parse value\n", BOLD, RED, NORMAL);
        return;
    }

    i8 ret = breakpoint_new(cfg, addr);
    if (ret < 0) {
        printf("%s%serror:%s failed to create new breakpoint\n", BOLD, RED, NORMAL);
    }
}

static
void switch_breakpoint(config_t* cfg, size_t const id, int const mode)
{
    if (mode == ENABLE) {
        i8 ret = breakpoint_enable_id(cfg, id);
        if (ret < 0) {
            printf("%s%serror:%s failed to enable breakpoint #%zu\n", BOLD, RED, NORMAL, id);
        }
        printf("Enabled breakpoint #%zu\n", id + 1);
    } else {
        i8 ret = breakpoint_disable_id(cfg, id);
        if (ret < 0) {
            printf("%s%serror:%s failed to disable breakpoint #%zu\n", BOLD, RED, NORMAL, id);
        }
        printf("Disabled breakpoint #%zu\n", id + 1);
    }
}

void command_enable(config_t* cfg, char* value)
{
    if (cfg->state == STATE_UNINIT) {
        printf("%s%serror:%s debugger has not been initialized yet\n", BOLD, RED, NORMAL);
        return;
    }

    size_t id = SIZE_MAX - 1;
    if (value) {
        id = parse_value(value);
        if (id == SIZE_MAX) {
            printf("%s%serror:%s failed to parse value\n", BOLD, RED, NORMAL);
            return;
        }
    }

    if (id != SIZE_MAX - 1) {
        switch_breakpoint(cfg, id - 1, ENABLE);
    } else {
        for (size_t i = 0; i < cfg->breakpoints->len; i++) {
            switch_breakpoint(cfg, i, ENABLE);
        }
    }
}

void command_disable(config_t* cfg, char* value)
{
    if (cfg->state == STATE_UNINIT) {
        printf("%s%serror:%s debugger has not been initialized yet\n", BOLD, RED, NORMAL);
        return;
    }

    size_t id = SIZE_MAX - 1;
    if (value) {
        id = parse_value(value);
        if (id == SIZE_MAX) {
            printf("%s%serror:%s failed to parse value\n", BOLD, RED, NORMAL);
            return;
        }
    }

    if (id != SIZE_MAX - 1) {
        switch_breakpoint(cfg, id - 1, DISABLE);
    } else {
        for (size_t i = 0; i < cfg->breakpoints->len; i++) {
            switch_breakpoint(cfg, i, DISABLE);
        }
    }
}

void command_help()
{
    printf("%sAvailable commands:%s\n", BOLD, NORMAL);
    printf("    %sload,         l <path> %s-- Load debugger with the given program's path.\n", BOLD, NORMAL);
    printf("    %sinfo,         i        %s-- Print current debugger configuration.\n", BOLD, NORMAL);
    printf("    %srun,          r [args] %s-- Launch the program in the debugger (with optional arguments).\n", BOLD, NORMAL);
    printf("    %sbreak,        b <addr> %s-- Set a breakpoint at the given address (hexadecimal format).\n", BOLD, NORMAL);
    printf("    %senable,       e [id]   %s-- Enable the breakpoint with the given ID (enables all breakpoints if no ID is specified.\n", BOLD, NORMAL);
    printf("    %sdisable,      d [id]   %s-- Disable the breakpoint with the given ID (disables all breakpoints if no ID is specified.\n", BOLD, NORMAL);
    printf("    %slist,         L        %s-- List breakpoints.\n", BOLD, NORMAL);
    printf("    %sbacktrace,    B        %s-- Backtrace the current stack.\n", BOLD, NORMAL);
    printf("    %spids,         p        %s-- Print main's & inferior's pids.\n", BOLD, NORMAL);
    printf("    %spath,         p        %s-- Print the debugged file path.\n", BOLD, NORMAL);
    printf("    %sdebug_str,    D        %s-- Print debug_str dwarf info.\n", BOLD, NORMAL);
    printf("    %smemmaps,      m        %s-- Print memory maps.\n", BOLD, NORMAL);
    printf("    %smemory,       M        %s-- Print memory usage status.\n", BOLD, NORMAL);
    printf("    %slibs,         T        %s-- Print program libraries.\n", BOLD, NORMAL);
    printf("    %sshared_libs,  S        %s-- Print only the program shared libraries.\n", BOLD, NORMAL);
    printf("    %sregisters,    R        %s-- Print registers status.\n", BOLD, NORMAL);
    printf("    %skill,         k        %s-- Send signal SIGKILL to debugged program.\n", BOLD, NORMAL);
    printf("    %shelp,         h        %s-- Print the available debugger commands.\n", BOLD, NORMAL);
    printf("    %squit,         q        %s-- Quit the debugger.\n\n", BOLD, NORMAL);
}

void command_kill(config_t* cfg, char const* signal)
{
    if (!signal) {
        debugger_kill(cfg, SIGKILL);
    }
    // Handle what signals can we send to the child
    i32 sig = SIGKILL;
    debugger_kill(cfg, sig);
}

bool command_quit(config_t* cfg)
{
    if (cfg->state == STATE_RUNNING) {
        printf("Inferior process %d is currently being debugged.\n", cfg->pid);
        printf("Are you sure you want to quit? [y/n] ");
        char ans[BUFFER_LEN];
        scanf("%s", ans);
        if (ans[0] == 'y' || ans[0] == 'Y') {
            i32 ret = debugger_kill(cfg, SIGKILL);
            UDB_assert(ret <= 0, "failed to kill child process");
        } else if (ans[0] == 'n' || ans[0] == 'N') {
            printf("Continuing debugging session\n");
            return true;
        } else {
            printf("\n%s%serror:%s `%s` is not a valid answer\n", BOLD, RED, NORMAL, ans);
            return true;
        }
    }
    config_drop(*cfg);
    printf("\nBye :)\n");
    return false;
}

void command_run(config_t* cfg, char** args)
{
    if (!cfg->path) {
        printf("%s%serror:%s no executable has been defined yet\n", BOLD, RED, NORMAL);
        return;
    }
    if (access(cfg->path, F_OK) != 0 || access(cfg->path, X_OK != 0)) {
        printf("%s%serror:%s executable does not exist or has not the required permissions\n",
               BOLD, RED, NORMAL);
        return;
    }

    cfg->state = STATE_RUNNING;
    debugger_run(cfg, args);
}

bool handle_command(char* prompt, config_t* cfg)
{
    char* cmd = strtok(prompt, " "); 
    if (!cmd) {
        return true;
    }

    if (!strcmp(cmd, "b") || !strcmp(cmd, "break")) {
        char* value = strtok(NULL, " ");
        if (!value) {
            printf("%s%serror:%s command `break` takes at least one argument\n", BOLD, RED, NORMAL);
            return true;
        }
        command_break(cfg, value);
    }
    else if (!strcmp(cmd, "B") || !strcmp(cmd, "backtrace")) {
        debugger_backtrace(cfg->pid);
    } else if (!strcmp(cmd, "c") || !strcmp(cmd, "cont")) {
        debugger_cont(cfg);
    } else if (!strcmp(cmd, "e") || !strcmp(cmd, "enable")) {
        char* value = strtok(NULL, " ");
        // if (!value) {
        //     printf("%s%serror:%s command `enable` takes at least one argument\n", BOLD, RED, NORMAL);
        //     return true;
        // }
        command_enable(cfg, value);
    } else if (!strcmp(cmd, "d") || !strcmp(cmd, "disable")) {
        char* value = strtok(NULL, " ");
        // if (!value) {
        //     printf("%s%serror:%s command `disable` takes at least one argument\n", BOLD, RED, NORMAL);
        //     return true;
        // }
        command_disable(cfg, value);
    } else if (!strcmp(cmd, "h") || !strcmp(cmd, "help")) {
        command_help();
    } else if (!strcmp(cmd, "i") || !strcmp(cmd, "info")) {
        config_print(cfg);
    } else if (!strcmp(cmd, "k") || !strcmp(cmd, "kill")) {
        char* signal = strtok(NULL, " ");
        command_kill(cfg, signal);
    } else if (!strcmp(cmd, "l") || !strcmp(cmd, "load")) {
        char* target = strtok(NULL, " ");
        if (!target) {
            printf("%s%serror:%s command `target` takes at least one argument\n", BOLD, RED, NORMAL);
        } else if (substr_cnt(target, " ") > 1) {
            printf("%s%swarning:%s command `target` only takes one argument\n", BOLD, YELLOW, NORMAL);
        } else {
            config_load(cfg, target);
        }
    } else if (!strcmp(cmd, "L") || !strcmp(cmd, "list")) {
        breakpoint_list(cfg);
    } else if (!strcmp(cmd, "m") || !strcmp(cmd, "memmaps")) {
        debugger_print_mem_maps(cfg);
    } else if (!strcmp(cmd, "M") || !strcmp(cmd, "memory")) {
        debugger_print_mem();
    } else if (!strcmp(cmd, "D") || !strcmp(cmd, "debug_str")) {
        debugger_print_debug_strings(cfg);
    } else if (!strcmp(cmd, "q") || !strcmp(cmd, "quit")) {
        return command_quit(cfg);
    } else if (!strcmp(cmd, "r") || !strcmp(cmd, "run")) {
        char* argv[MAX_ARGS + 1];
        for (size_t i = 0; i < MAX_ARGS; i++) {
            argv[i] = strtok(NULL, " ");
            if (argv[i] == NULL) {
                break;
            }
        }
        argv[MAX_ARGS] = NULL;
        command_run(cfg, argv);
    } else if (!strcmp(cmd, "s") || !strcmp(cmd, "step")) {
        breakpoint_step(cfg);
    } else if (!strcmp(cmd, "R") || !strcmp(cmd, "registers")) {
        debugger_print_regs(cfg);
    } else if (!strcmp(cmd, "T") || !strcmp(cmd, "libs")) {
        debugger_print_libraries(cfg);
    } else if (!strcmp(cmd, "S") || !strcmp(cmd, "shared_libs")) {
        debugger_print_shared_libraries(cfg);
    } else if (!strcmp(cmd, "pids")) {
        debugger_pids(cfg);
    } else if (!strcmp(cmd, "path")) {
        debugger_print_real_path(cfg);
    } else {
        printf("%s%serror:%s `%s` is an unknow command\n", BOLD, RED, NORMAL, cmd);
        printf("Type `h` or `help` to display available commands\n");
    }

    return true;
}
