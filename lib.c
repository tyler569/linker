#include <sys/syscall.h>

typedef unsigned long ulong;

static long __syscall1(ulong number, ulong arg) {
    long ret;
    asm volatile (
        "syscall"
        : "=a"(ret)
        : "0"(number),
          "D"(arg)
        : "memory"
    );
}

static long __syscall3(ulong number, ulong a1, ulong a2, ulong a3) {
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

static ulong strlen(const char *str) {
    for (ulong i=0; ; i++) {
        if (str[i] == 0)  return i;
    }
}

void lprint(const char *message) {
    ulong len = strlen(message);
    __syscall3(__NR_write, 1, (ulong)message, len);
}

int _start() {
    int lmain();
    lmain();
    __syscall1(__NR_exit, 0);
}

