CC=gcc
CFLAGS=-Wall -Wextra -g3
OFLAGS=-march=native -mtune=native -O1

hello: src/hello.c
	@mkdir target
	$(CC) $(CFLAGS) $(OFLAGS) $^ -o target/$@

clean:
	rm -rf target
