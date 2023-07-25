// [Changelog]
// uaf1 -> off_by_null: fix uaf, introduce off_by_null in read_buf()
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

char* buf[16];
int sizes[16];

void read_buf(char *p, uint32_t size) {
    int len = 0;
    while (len < size) {
        int ret = read(0, p + len, 1);
        if (ret == -1) {
            exit(-1);
        }

        if (p[len] == '\n') {
            p[len] = '\x00';
            return;
        }
        len += 1;
    }
    p[len] = '\x00';
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
    buf[idx] = 0;
}

void write_chunk() {
    uint32_t idx;
    printf("idx: \n");
    scanf("%u", &idx);
    if (idx >= 16 || buf[idx] == NULL)
        exit(-1);

    printf("%s", buf[idx]);
}

void read_chunk() {
    uint32_t idx;
    printf("idx: \n");
    scanf("%u", &idx);
    if (idx >= 16 || buf[idx] == NULL)
        exit(-1);
    
    printf("data: \n");
    read_buf(buf[idx], sizes[idx]);
}



void init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
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