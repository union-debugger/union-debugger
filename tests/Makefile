CC?=gcc
CFLAGS?=-g -O0

ALL_C=$(wildcard *.c)
ALL_T=$(patsubst %.c,%.bin,$(ALL_C))

all: $(ALL_T)

%.bin: %.c
	$(CC) $(CFLAGS) $< -o $@ -lpthread

clean:
	rm -f $(ALL_T)
