
#include <ng/basic.h>
#include <ng/elf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// host-specific
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


void *load_file(const char *filename, int write) {
        struct stat sb;
        int fd = open(filename, O_RDWR);

        if (fd < 0) {
                perror("open()");
                exit(EXIT_FAILURE);
        }

        fstat(fd, &sb);

        void *map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);

        if ((long)map == -1) {
                perror("mmap()");
                exit(EXIT_FAILURE);
        }

        return map;
}

int main() {
        const char *ngk = "./demo";
        const char *mod = "./mod.o";

        void *ngk_elf = load_file(ngk, 0);
        void *mod_elf = load_file(mod, 1);

        /*elf_debugprint(ngk_elf);
        elf_print_syms(ngk_elf);

        elf_debugprint(mod_elf);
        elf_print_syms(mod_elf);
        */

        printf("ngk_1 is at %lx\n", elf_get_sym_off("ngk_1", ngk_elf));
        printf("mod_1 is at %lx\n", elf_get_sym_off("mod_1", mod_elf));

        // elf_print_rels(mod_elf);

        elf_print_syms(mod_elf);
        elf_resolve_symbols_from_elf(ngk_elf, mod_elf);
        elf_print_syms(mod_elf);

        printf("\n\n == relocating object ==\n\n");

        elf_relocate_object(mod_elf, 0x800000);

        return 0;
}

