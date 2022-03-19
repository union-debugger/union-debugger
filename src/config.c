#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../include/breakpoint.h"
#include "../include/config.h"
#include "../include/utils.h"

config_t* config_new(char* target)
{
    config_t* cfg = malloc(sizeof(config_t));
    UD_assert(cfg, "config allocation failed");
    cfg->target = target;
    cfg->pid = getpid();
    cfg->inferior_pid = -1;
    cfg->inferior_start = 0;
    cfg->breakpoints = vec_new(sizeof(breakpoint_t));
    cfg->state = STATE_UNINIT;
    return cfg;
}

void config_clear(config_t* self)
{
    UD_assert(self, "invalid parameter (null pointer)");
    free(self->target);
    self->inferior_pid = -1;
    self->inferior_start = 0;
    vec_drop(self->breakpoints);
    self->state = STATE_UNINIT;
}

void config_drop(config_t* self)
{
    UD_assert(self, "invalid parameter (null pointer)");
    config_clear(self);
    free(self);
}

void config_load(config_t* self, char const* target)
{
    UD_assert(self && target, "invalid parameter (null pointer)");
    if (self->target) {
        printf("Executable has already been loaded\n");
        return;
    }
    self->target = strdup(target);
    UD_assert(self->target, "config's target allocation failed");

    self->target = strdup(target);
    UD_assert(self->target, "failed to duplicate target path");

    FILE* fd = fopen(target, "rb");
    UD_assert(fd, "failed to open target binary");

    u8 elf_buf[sizeof(Elf64_Ehdr)];
    size_t nread = fread(elf_buf, sizeof(Elf64_Ehdr), 1, fd);
    fclose(fd);
    UD_assert(nread == 1, "failed to read ELF header");

    Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)(elf_buf);
    UD_assert(elf_hdr->e_ident[EI_MAG0] == ELFMAG0 && elf_hdr->e_ident[EI_MAG1] == ELFMAG1 &&
              elf_hdr->e_ident[EI_MAG2] == ELFMAG2 && elf_hdr->e_ident[EI_MAG3] == ELFMAG3 &&
              elf_hdr->e_ident[EI_CLASS] == ELFCLASS64 && elf_hdr->e_machine == EM_X86_64,
              "ELF is invalid");

    self->inferior_start = elf_hdr->e_entry;
    self->state = STATE_INIT;
    config_print(self);
}

void config_print(config_t const* self)
{
    UD_assert(self, "invalid parameter (null pointer)");
    printf("Current executable is set to `%s`, PID #%d (start address: 0x%zx)\n",
           self->target, self->inferior_pid, self->inferior_start);
}
