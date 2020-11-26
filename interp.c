#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern uintptr_t _GLOBAL_OFFSET_TABLE_[];
extern char _DYNAMIC[];

void _start() {
    // uintptr_t dynamic_offset = _GLOBAL_OFFSET_TABLE_[0];
    uintptr_t dynamic_load = (uintptr_t)&_DYNAMIC;

    printf("Hello World\n");
    printf("Load offset is %#lx\n", dynamic_load);

    exit(0);
}
