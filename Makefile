CC=gcc
CFLAGS=-Wall -Wextra -g3
OFLAGS=-march=native -mtune=native -O2 -Os

SRC=src
EXT=ext
TEST=tests
TARGET=target
DEPS=target/deps
BINS=target/$(TEST)
EXE=udb

build: $(DEPS)/linenoise.o $(DEPS)/vec.o $(DEPS)/main.o $(DEPS)/breakpoint.o $(DEPS)/config.o $(DEPS)/cli.o $(DEPS)/debugger.o $(DEPS)/utils.o
	$(CC) $(CFLAGS) $(OFLAGS) $? -o $(EXE)

test: $(BINS)/hello $(BINS)/loop $(BINS)/mini_segfault

$(DEPS)/%.o: $(SRC)/%.c
	@mkdir -p $(DEPS)
	$(CC) $(CFLAGS) $(OFLAGS) -c $^ -o $@

$(DEPS)/%.o: $(EXT)/%.c
	@mkdir -p $(DEPS)
	$(CC) $(CFLAGS) $(OFLAGS) -c $^ -o $@

$(BINS)/%: $(TEST)/%.c
	@mkdir -p $(BINS)
	$(CC) $(CFLAGS) $(OFLAGS) $^ -o $@

clean:
	rm -Rf $(TARGET) $(EXE)
