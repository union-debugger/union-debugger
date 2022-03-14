#include <stdio.h>
#include <stdlib.h>

#include "../include/cli.h"
#include "../include/consts.h"
#include "../include/types.h"
#include "../include/utils.h"

int main(int argc, char **argv)
{
    config_t* cfg = parse_args(argc, argv);

    printf("\n%s%sUnion's Debugging Software (udb) v0.1.0%s\n", MAGENTA, BOLD, NORMAL);
    printf("To show the available commands, type `help`.\n\n");
    char* cmd_buffer = malloc(BUFFER_LEN * sizeof(char));
    do {
        printf("%s(udb) >%s ", BLUE, NORMAL);
        fgets(cmd_buffer, BUFFER_LEN, stdin);
        cmd_buffer = strstrip(cmd_buffer);
    } while (handle_command(cmd_buffer, cfg) != 0);

    free(cmd_buffer);
    free(cfg);
    return 0;
}
