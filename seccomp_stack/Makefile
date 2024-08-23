CC=gcc
CFLAGS=-g -Wall -no-pie -fno-stack-protector

all: seccomp_stack_self_built

seccomp_stack_self_built: seccomp_stack.c
	$(CC) $(CFLAGS) -o seccomp_stack_self_built seccomp_stack.c

clean:
	rm -f seccomp_stack_self_built
