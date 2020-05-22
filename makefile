
INCLUDE := -Iinclude
CFLAGS += $(INCLUDE)

XCFLAGS := $(CFLAGS) -fpic -nostdlib -shared -I.

.PHONY: all

all: link-ng liblib.so lmain

link-ng: link-ng.c
	$(CC) $(CFLAGS) $< -o $@

liblib.so: lib.c lib.h
	$(CC) -I. -fpic -nostdlib -shared $< -o $@

lmain.o: lmain.c lib.h
	$(CC) -I. -fpic -nostdlib -c $< -o $@

lmain: lmain.o liblib.so
	ld -o $@ -dynamic-linker /home/tyler/dyld -L. -llib $<

clean:
	rm -f link-ng lmain *.so *.o
