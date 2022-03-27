#include <elf.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../include/breakpoint.h"
#include "../include/config.h"
#include "../include/debugger.h"
#include "../include/utils.h"

#define no_argument 0
#define required_argument 1 
#define optional_argument 2

Elf64_Ehdr* read_elf_header(char const* path)
{
    FILE* fd = fopen(path, "rb");
    UDB_assert(fd, "failed to open target binary");

    u8* buffer = malloc(sizeof(Elf64_Ehdr));
    size_t nb_read = fread(buffer, sizeof(Elf64_Ehdr), 1, fd);
    UDB_assert(nb_read == 1, "failed to read ELF header");
    fclose(fd);

    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)(buffer);
    UDB_assert(elf_header->e_ident[EI_MAG0] == ELFMAG0 && elf_header->e_ident[EI_MAG1] == ELFMAG1 &&
               elf_header->e_ident[EI_MAG2] == ELFMAG2 && elf_header->e_ident[EI_MAG3] == ELFMAG3 &&
               elf_header->e_ident[EI_CLASS] == ELFCLASS64 && elf_header->e_machine == EM_X86_64,
               "ELF header is not valid");

    return elf_header;
}

void config_load(config_t* self, char const* path)
{
    if (self->state == DBG_RUNNING) {
        printf("Inferior process %d is currently being debugged.\n", self->pid);
        bool ans = ask_user();
        if (ans) {
            i32 ret = debugger_kill(self, SIGKILL);
            UDB_assert(ret <= 0, "failed to kill child process");
        } else {
            printf("Continuing debugging session.\n");
            return;
        }
    }

    if (path) {
        self->state = DBG_LOADED;
        self->path = strdup(path);
        UDB_assert(self->path, "failed to duplicate path");
        Elf64_Ehdr* elf_header = read_elf_header(self->path);
        UDB_assert(elf_header, "failed to read ELF header");
        self->entry_address = elf_header->e_entry;
        free(elf_header);
        printf("%s%sinfo:%s current executable set to '%s'.\n", BOLD, CYAN, NORMAL, self->path);
    } else {
        self->state = DBG_UNINIT;
        self->path = NULL;
        self->entry_address = 0;
    }
    self->pid = 0;
    if (!self->breakpoints) {
        self->breakpoints = vec_new(sizeof(breakpoint_t));
    }
}

config_t parse_args(int const argc, char* const* argv)
{
    struct option const long_options[] = {
        { "path",    required_argument, 0, 'p' },
        { "args",    required_argument, 0, 'a' },
        { "version", no_argument,       0, 'v' },
        { "help",    no_argument,       0, 'h' },
        { 0,         0,                 0, 0   },
    };

    config_t cfg = {
        .state = DBG_UNINIT,
        .path = NULL,
        .pid = 0,
        .entry_address = 0,
        .breakpoints = vec_new(sizeof(breakpoint_t)),
    };
    i32 current;
    do {
        i32 option_idx;
        current = getopt_long(argc, argv, "p:vh", long_options, &option_idx);
        switch (current) {
        case 'p':
            config_load(&cfg, optarg);
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
            return cfg;
        }
    } while (current < 0);

    return cfg;
}

void config_print(config_t const* self)
{
    UDB_assert(self, "invalid parameter (null pointer)");
    printf("Current configuration:\n");
    if (self->state == DBG_UNINIT) {
        printf("  State: %s%s%s\n", BOLD, "Uninitialized", NORMAL);
        printf("  Path:  %s%s%s\n", BOLD, "-", NORMAL);
        printf("  PID:   %s%d%s\n", BOLD, self->pid, NORMAL);
        printf("  Entry: %s0x%lx%s\n", BOLD, self->entry_address, NORMAL);
        printf("No breakpoints currently set.\n");
    } else {
        printf("  State: %s%s%s\n", BOLD, self->state == DBG_LOADED ? "Loaded" : "Running", NORMAL); 
        printf("  Path:  %s%s%s\n", BOLD, self->path, NORMAL);
        printf("  PID:   %s%d%s\n", BOLD, self->pid, NORMAL);
        printf("  Entry: %s0x%lx%s\n", BOLD, self->entry_address, NORMAL);
        breakpoint_list(self);
    }
}

void config_drop(config_t self)
{
    self.state = DBG_UNINIT;
    if (self.path) {
        free(self.path);
    }
    self.pid = 0;
    self.entry_address = 0;
    vec_drop(self.breakpoints);
}
