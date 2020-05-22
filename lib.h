
#ifndef _LIB_H_
#define _LIB_H_

typedef unsigned long ulong;

long __syscall1(ulong, ulong);
long __syscall3(ulong, ulong, ulong, ulong);

void lprint(const char *);

#endif
