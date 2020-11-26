
INCLUDE := -Iinclude
CFLAGS += $(INCLUDE) -g -fsanitize=address

.PHONY: all

all: link-ng link-rel lib.ko lib.o liblib.so lmain

link-ng: link-ng.c elf-ng.c pltstub.S
	$(CC) $(CFLAGS) $^ -o $@

link-rel: link-ngrel.c elf-ng.c
	$(CC) $(CFLAGS) $^ -o $@

lib.o: lib.c lib.h
	$(CC) -c -I. -fpic -nostdlib $< -o $@

lib.ko: lib.c lib.h
	$(CC) -c -I. -static -fno-pic -nostdlib $< -o $@

liblib.so: lib.o
	$(CC) -fpie -nostdlib -shared $< -o $@

rt.o: rt.c
	$(CC) -I. -fpic -nostdlib -c $< -o $@

lmain.o: lmain.c lib.h
	$(CC) -I. -fpic -nostdlib -c $< -o $@

lmain: lmain.o rt.o liblib.so
	ld -o $@ -pie -dynamic-linker /home/tyler/dyld -L. rt.o $< -llib

clean:
	rm -f link-ng link-rel lmain *.so *.o
