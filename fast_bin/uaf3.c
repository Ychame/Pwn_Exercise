// [Changelog]
// uaf2 -> uaf3: Use calloc instead of malloc

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

char* buf[16];
int sizes[16];
bool flag[16];

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

    char *p = calloc(1, size);
    if (!p)
        exit(-1);

    buf[idx] = p;
    sizes[idx] = size;
    flag[idx] = true;
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
    flag[idx] = false;
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
    if (idx >= 16 || buf[idx] == NULL || !flag[idx])
        exit(-1);

    printf("%s", buf[idx]);
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