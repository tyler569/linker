
INCLUDE := -Iinclude
CFLAGS += $(INCLUDE)

.PHONY: all

all: link-ng liblib.so lmain

link-ng: link-ng.c
	$(CC) $(CFLAGS) $< -o $@

liblib.so: lib.c lib.h
	$(CC) -I. -fpic -nostdlib -shared $< -o $@

rt.o: rt.c
	$(CC) -I. -fpic -nostdlib -c $< -o $@

lmain.o: lmain.c lib.h
	$(CC) -I. -fpic -nostdlib -c $< -o $@

lmain: lmain.o rt.o liblib.so
	ld -o $@ -dynamic-linker /home/tyler/dyld -L. rt.o $< -llib

clean:
	rm -f link-ng lmain *.so *.o
