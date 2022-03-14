CC=gcc
CFLAGS=-Wall -Wextra -g3
OFLAGS=-march=native -mtune=native -O1

SRC=src
TEST=test
TARGET=target
BINS=target/tests
DEPS=target/deps

build: $(DEPS)/main.o $(DEPS)/config.o $(DEPS)/cli.o $(DEPS)/debugger.o $(DEPS)/utils.o
	$(CC) $(CFLAGS) $(OFLAGS) $? -o udb

$(DEPS)/%.o: $(SRC)/%.c
	@mkdir -p $(DEPS)
	$(CC) $(CFLAGS) $(OFLAGS) -c $^ -o $@
	
$(BINS)/%: $(TEST)/%.c
	@mkdir -p $(BINS)
	$(CC) $(CFLAGS) $(OFLAGS) $^ -o $@

clean:
	rm -Rf $(TARGET) udb
