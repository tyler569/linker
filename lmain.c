
#include <lib.h>

int bss_symbol;
int data_symbol = 100;

int lmain() {
    lprint("Hello World\n");
    lprint("Let's make sure it doesn't resolve a second time\n");
    inc_global();
    ulong c = some_global;
    ulong *d = &some_global;
    bss_symbol = (unsigned long)&c;
    data_symbol = (unsigned long)d;
    return 0;
}
