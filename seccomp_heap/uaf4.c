// [Changelog]
// uaf1 -> uaf4: Add seccomp filter

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include "seccomp-bpf.h"

char* buf[16];
int sizes[16];

static int install_syscall_filter(void)
{
	struct sock_filter filter[] = 
	{
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(writev),
        ALLOW_SYSCALL(brk),
		ALLOW_SYSCALL(lseek),
		ALLOW_SYSCALL(open),
		ALLOW_SYSCALL(close),
		KILL_PROCESS,
	};

	struct sock_fprog prog = 
	{
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ) 
	{
		perror("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if ( prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) ) 
	{
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if ( errno == EINVAL )
	{
		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
	}

	return 1;
}

void alloc_chunk() {
    uint32_t idx, size;

    printf("idx: \n");
    scanf("%u", &idx);
    if (idx >= 16)
        exit(-1);

    printf("size: \n");
    scanf("%u", &size);
    if (size > 0x1000)
        exit(-1);

    char *p = malloc(size);
    if (!p)
        exit(-1);

    buf[idx] = p;
    sizes[idx] = size;
}

void free_chunk() {
    uint32_t idx;
    printf("idx: \n");
    scanf("%u", &idx);
    if (idx >= 16)
        exit(-1);

    if (buf[idx] == NULL)
        return;

    free(buf[idx]);
}

void read_chunk() {
    uint32_t idx;
    printf("idx: \n");
    scanf("%u", &idx);
    if (idx >= 16 || buf[idx] == NULL)
        exit(-1);
    
    printf("data: \n");
    read(0, buf[idx], sizes[idx]);
}

void write_chunk() {
    uint32_t idx;
    printf("idx: \n");
    scanf("%u", &idx);
    if (idx >= 16 || buf[idx] == NULL)
        exit(-1);

    printf("%s", buf[idx]);
}

void init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    install_syscall_filter();
}

void menu() {
    printf("1. alloc\n2. free\n3. read\n4. write\n> ");
}

int main() {

    init();
    printf("Tcache attack\n");
    int choice;
    while(1) {
        menu();
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                alloc_chunk();
                break;

            case 2:
                free_chunk();
                break;

            case 3:
                read_chunk();
                break;

            case 4:
                write_chunk();
                break;

            default: {
                exit(-1);
            }
        }
    }
}