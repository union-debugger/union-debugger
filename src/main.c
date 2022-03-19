#include <stdio.h>

#include "../ext/linenoise.h"
#include "../include/cli.h"
#include "../include/consts.h"
#include "../include/types.h"
#include "../include/utils.h"
#include "../include/debugger.h"

int main(int argc, char** argv)
{
    config_t cfg = parse_args(argc, argv);
    linenoiseSetCompletionCallback(completions);
    linenoiseHistoryLoad(UDB_HISTORY);
    printf("\n%s%sUnion's Debugger (udb) v0.1.0%s\n", MAGENTA, BOLD, NORMAL);
    printf("To show the available commands, type `help`.\n\n");

    bool ret = true;
    while (ret == true) {
        char* prompt_buffer;
        prompt_buffer = linenoise("\033[34m(udb) >\033[0m ");
        linenoiseHistoryAdd(prompt_buffer);
        linenoiseHistorySave(UDB_HISTORY);
        ret = handle_command(prompt_buffer, &cfg);
        free(prompt_buffer);
    }

    return 0;
}
