
#ifndef _LIB_H_
#define _LIB_H_

typedef unsigned long ulong;

extern ulong some_global;
void inc_global();

long __syscall1(ulong, ulong);
long __syscall3(ulong, ulong, ulong, ulong);

void lprint(const char *);

#endif
