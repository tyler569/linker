#include <lib.h>
#include <sys/syscall.h>

int _start() {
    int lmain();
    lmain();
    __syscall1(__NR_exit, 0);
}
