CC=gcc
CFLAGS=-Wall -Wextra -g3 -Wno-return-type -Wno-format
CTFLAGS=-w -Wextra -g3 # Compiler flags for tests only.
OFLAGS=-march=native -mtune=native -O2 -Os

SRC=src
EXT=ext
TEST=tests
TARGET=target
DEPS=target/deps
BINS=target/$(TEST)
_LIBS=capstone unwind unwind-ptrace unwind-generic dwarf elf
LIBS=$(foreach l,$(_LIBS),-l$l)
CTLIBS=-lpthread
EXE=udb

.PHONY: all build test clean

all: build test

build: $(DEPS)/linenoise.o $(DEPS)/vec.o $(DEPS)/main.o $(DEPS)/breakpoint.o $(DEPS)/config.o $(DEPS)/cli.o $(DEPS)/debugger.o $(DEPS)/utils.o
	$(CC) $(CFLAGS) $(OFLAGS) $? -o $(EXE) $(LIBS)

test: $(BINS)/hello $(BINS)/loop $(BINS)/mini_segfault $(BINS)/trace $(BINS)/dlk $(BINS)/mem $(BINS)/rogue $(BINS)/rogue_sp $(BINS)/stack $(BINS)/voidp

$(DEPS)/%.o: $(SRC)/%.c
	@mkdir -p $(DEPS)
	$(CC) $(CFLAGS) $(OFLAGS) -c $^ -o $@

$(DEPS)/%.o: $(EXT)/%.c
	@mkdir -p $(DEPS)
	$(CC) $(CFLAGS) $(OFLAGS) -c $^ -o $@

$(BINS)/%: $(TEST)/%.c
	@mkdir -p $(BINS)
	$(CC) $(CTFLAGS) $(OFLAGS) $^ -o $@ $(CTLIBS)

clean:
	rm -Rf $(TARGET) $(EXE)
