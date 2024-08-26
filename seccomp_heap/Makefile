CC=gcc
CFLAGS=-g -Wall

all: seccomp_heap_self_built

seccomp_heap_self_built: uaf4.c
	$(CC) $(CFLAGS) -o seccomp_heap_self_built uaf4.c

clean:
	rm -f seccomp_heap_self_built