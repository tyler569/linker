#include <sys/syscall.h>

typedef unsigned long ulong;

long __syscall1(ulong number, ulong arg) {
    long ret;
    asm volatile (
        "syscall"
        : "=a"(ret)
        : "0"(number),
          "D"(arg)
        : "memory"
    );
}

long __syscall3(ulong number, ulong a1, ulong a2, ulong a3) {
    long ret;
    asm volatile (
        "syscall"
        : "=a"(ret)
        : "0"(number),
          "D"(a1),
          "S"(a2),
          "d"(a3)
        : "memory"
    );
}

ulong strlen(const char *str) {
    for (ulong i=0; ; i++) {
        if (str[i] == 0)  return i;
    }
}

void lprint(const char *message) {
    ulong len = strlen(message);
    __syscall3(__NR_write, 1, (ulong)message, len);
}

void _start() {

    ulong ret;
    ulong number = __NR_write;
    ulong a1 = 1;
    ulong a2 = (ulong)"a\n";
    ulong a3 = 2;

    asm volatile (
        "syscall"
        : "=a"(ret)
        : "0"(number),
          "D"(a1),
          "S"(a2),
          "d"(a3)
        : "memory"
    );


    lprint("Hello world\n");
    __syscall1(__NR_exit, 0);
}
