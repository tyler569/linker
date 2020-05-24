
INCLUDE := -Iinclude
CFLAGS += $(INCLUDE) -g

.PHONY: all

all: link-ng liblib.so lmain

link-ng: link-ng.c pltstub.S
	$(CC) $(CFLAGS) $^ -o $@

liblib.so: lib.c lib.h
	$(CC) -I. -fpic -nostdlib -shared $< -o $@

rt.o: rt.c
	$(CC) -I. -fpic -nostdlib -c $< -o $@

lmain.o: lmain.c lib.h
	$(CC) -I. -fpic -nostdlib -c $< -o $@

lmain: lmain.o rt.o liblib.so
	ld -o $@ -pie -dynamic-linker /home/tyler/dyld -L. rt.o $< -llib

clean:
	rm -f link-ng lmain *.so *.o
