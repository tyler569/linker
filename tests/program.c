#include <sys/syscall.h>

long __syscall(unsigned number, unsigned arg) {
    long ret;
    asm volatile (
        "syscall"
        : "=a"(ret)
        : "0"(number),
          "D"(arg)
        : "memory"
    );
}

int main() {
    __syscall(__NR_exit, 0);
}

int _start() {
    main();
}
