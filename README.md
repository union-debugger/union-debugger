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
```
make
```
Then run the debugger on your binaries like so:
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

The debugger features a GDB/LLDB-like command line interface with various commands
allowing the user to perform the aforementionned actions on a debugged program.
Type `help` in the debugger to print all the available commands.

## Approach
We decided to make our debugger as an external process that attaches to the debugee
and controls its behavior remotely using the `ptrace` system call provided by the
Linux kernel.
We start by forking a child process that launches to program to debug. We can then
run it, set breakpoints, inspect its memory, registers, etc...
