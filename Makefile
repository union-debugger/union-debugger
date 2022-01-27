CC=gcc
CFLAGS=-Wall -Wextra -g3
OFLAGS=-march=native -mtune=native -O1

build: deps/main.o
	$(CC) $(CFLAGS) $(OFLAGS) $< -o udb

deps/%.o: src/%.c
	@mkdir -p deps/
	$(CC) $(CFLAGS) $(OFLAGS) -c $^ -o $@

clean:
	rm -rf deps/ udb
