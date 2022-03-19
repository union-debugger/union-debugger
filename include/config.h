#pragma once

#include "../ext/vec.h"
#include "types.h"

enum state_t {
    STATE_UNINIT,
    STATE_INIT,
    STATE_RUNNING,
};

typedef struct config_t {
    /// State of the debugger.
    enum state_t state;
    /// Path to the debugged program's binary.
    char* path;
    /// PID of the debugged program.
    pid_t pid;
    /// Address of the entry point in the debugged program's binary.
    uintptr_t entry_address;
    /// List of breakpoints set in the binary.
    vec_t* breakpoints;
} config_t;

/// Parses the arguments given to the debugger from the command line using
/// the `getopt_long` function and initializes a `config_t` structure.
/// 
/// If no arguments are given, defaults to an uninitialized configuration.
config_t parse_args(int const argc, char* const* argv);

/// Initializes the debugger's configuration from a given target file.
/// This allows the user to load a different program once in the debugger's
/// CLI through the `load` command. 
void config_load(config_t* self, char const* target);

/// Prints the current configuration.
void config_print(config_t const* self);

/// Deallocates a `config_t` structure.
void config_drop(config_t self);
