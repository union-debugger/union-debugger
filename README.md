# Analysis of running processes

The goal of this project is to design a tool that allows the user to understand
why his program is not running the way it is meant to. In essence, the idea is
to build something that offers the same basic functionnalities as a simple
debugger.

## Building
In order to build the project, the following dependencies must be installed on
the system:
- `libelf`
- `libdwarf`
- `libunwind`

Use the provided Makefile to build the projet:
```sh
make build
# Optionally, you can build our test programs with the following:
make test
```
Then run the debugger on your binaries like so (where `OPTIONS` and `FLAGS` are optional):
```
./udb [OPTIONS] [FLAGS]
```

## Features
The debugger currently offers the following features:
- loading a program and reading its ELF header;
- getting PID, path, memory maps, memory usage, register status and DWARF debug info;
- sending signals to a program;
- running a program (with or without arguments);
- single stepping in a program;
- catching signals and printing them;
- setting breakpoints at given addresses in the program;
- enabling, disabling or listing breakpoints;
- backtracing an error (unfinished).

The debugger features a GDB/LLDB-like command line interface with various
commands and auto-complete (using `linenoise`) allowing the user to perform
the aforementionned actions on a debugged program.
Type `help` in the debugger to print all the available commands.

## Approach
We decided to make our debugger as an external process that attaches to the
debugee and controls its behavior remotely using the `ptrace` system call
provided by the Linux kernel.
We start by forking a child process that launches to program to debug. We can
then run it, set breakpoints, inspect its memory, registers, etc...

Quick summary of what we used:
- `linenoise & getopt()` for a lightweight command line interface for autocompletion and history support, and for argument parsing;
- `vec` for simplified and improved storage of debugger structures;
- `fork() & ptrace()` manage the basic behavior of a child process that will run the program to be debugged;
- `libdwarf & gelf` to read the program's debugging sections;
- `libunwind` for backtrace support;

**Did you know?**
We used the `vec` library, which provides a generic, growable array type written
in pure C.
This allows us to store any datatypes in a vector-like structure (*facon*
`std::vector<T>` from C++'s std library or Rust's `Vec<T>`). As this library
was written by Gabriel, we definitely deserve a few more points right? :P
