
ifeq ($(CFLAGS),)
	CFLAGS := -g
endif

INCLUDE := -Iinclude/linker -Iinclude

.PHONY: mod.o

all: demo mod.o link

link: link.c elf.c
	$(CC) $(CFLAGS) $(INCLUDE) link.c elf.c -o link

demo: demo.c elf.c
	$(CC) $(CFLAGS) $(INCLUDE) demo.c elf.c -static -o demo

mod.o:
	$(CC) -c mod.c -o mod.o

liblinker.a:
	$(CC) $(CFLAGS) $(INCLUDE) -c elf.c -o elf.o
	ar rcs liblinker.a elf.o

clean:
	rm -f demo mod.o link elf.o liblinker.a
