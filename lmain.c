
#include <lib.h>

int lmain() {
    lprint("Hello World\n");
    lprint("Let's make sure it doesn't resolve a second time\n");
    inc_global();
    ulong c = some_global;
    ulong *d = &some_global;
    return 0;
}
