
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "linker/elf.h"

void fail(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

struct elf_metadata {
    void *mem;
    Elf *image;

    Elf_Shdr *section_headers;

    Elf_Shdr *shdr_string_table_section;
    const char *shdr_string_table;
    Elf_Shdr *symbol_table_section;
    int symbol_count;
    Elf_Sym *symbol_table;

    Elf_Shdr *string_table_section;
    const char *string_table;

    Elf_Phdr *program_headers;

    Elf_Dyn *dynamic_table;
    int dynamic_count;
};
typedef struct elf_metadata elf_md;


void elf_print(elf_md *e) {
    printf("elf @ %p\n", e->mem);
}

/*
 * Always returns the first matching header, if you need multiple (i.e. all
 * the PT_LOADs, just iterate yourself.)
 */
Elf_Phdr *elf_find_phdr(elf_md *e, int p_type) {
    if (!e->program_headers)  return NULL;

    for (int i=0; i<e->image->e_phnum; i++) {
        Elf_Phdr *hdr = e->program_headers + i;
        if (hdr->p_type == p_type)  return hdr;
    }
    return NULL;
}

Elf_Dyn *elf_find_dyn(elf_md *e, int d_tag) {
    Elf_Dyn *d = e->dynamic_table;
    if (!d)  return NULL;

    for (d; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == d_tag)  return d;
    }
    return NULL;
}

Elf_Shdr *elf_find_section(elf_md *e, const char *name) {
    Elf *elf = e->image;

    if (elf->e_shnum == 0) {
        return NULL;
    }

    Elf_Shdr *shdr_table = e->section_headers;
    if (!shdr_table)  return NULL;

    for (int i=0; i<elf->e_shnum; i++) {
        Elf_Shdr *shdr = shdr_table + i;
        const char *sh_name = e->shdr_string_table + shdr->sh_name;
        if (strcmp(sh_name, name) == 0)  return shdr;
    }
    return NULL;
}

Elf_Sym *elf_find_symbol(elf_md *e, const char *name) {
    // TODO: symbol hash table lookups
    Elf_Sym *sym_tab = e->symbol_table;
    if (!sym_tab)  return 0;

    int symbol_table_count = e->symbol_table_section->sh_size / sizeof(Elf_Sym);

    for (int i=0; i<symbol_table_count; i++) {
        Elf_Sym *symbol = sym_tab + i;
        const char *symbol_name = e->string_table + symbol->st_name;
        if (strcmp(name, symbol_name) == 0) {
            return symbol;
        }
    }
    return NULL;
}

elf_md *elf_parse(void *memory) {
    elf_md *e = calloc(1, sizeof(*e));
    Elf *elf = memory;

    e->image = elf;
    e->mem = memory;

    if (elf->e_shnum > 0) {
        e->section_headers = memory + elf->e_shoff;
        e->shdr_string_table_section = e->section_headers + elf->e_shstrndx;
        e->shdr_string_table = memory + e->shdr_string_table_section->sh_offset;
    }

    e->string_table_section = elf_find_section(e, ".strtab");
    e->symbol_table_section = elf_find_section(e, ".symtab");

    if (e->string_table_section) {
        e->string_table = memory + e->string_table_section->sh_offset;
    }

    if (e->symbol_table_section) {
        e->symbol_table = memory + e->symbol_table_section->sh_offset;
    }

    if (elf->e_phnum > 0) {
        e->program_headers = memory + elf->e_phoff;
    }

    Elf_Phdr *dynamic_phdr = elf_find_phdr(e, PT_DYNAMIC);
    if (dynamic_phdr) {
        e->dynamic_table = e->mem + dynamic_phdr->p_offset;
        e->dynamic_count = dynamic_phdr->p_filesz / sizeof(Elf_Dyn);
    }

    return e;
}

/* Straight from the ELF spec */
unsigned long elf_hash(const unsigned char *name) {
    unsigned long h = 0, g;
    while (*name) {
        h = (h << 4) + *name++;
        if (g = h & 0xf0000000)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

/*
 * elf_load
 * elf_relocate ?? -- how does this work??
 * elf_link
 */


elf_md *elf_open(const char *name) {
    int fd = open(name, O_RDONLY);
    if (fd < 0)  fail("open");

    struct stat statbuf;
    fstat(fd, &statbuf);
    off_t len = statbuf.st_size;

    void *mem = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    elf_md *e = elf_parse(mem);
    return e;
}

// pltstub.S
void elf_lazy_resolve_stub();

void (*elf_lazy_resolve(elf_md *o, long symbol_index))() {
    printf("lazy resolving %li with elf %p\n", symbol_index, o);
    exit(0);
}

int main(int argc, char **argv) {
#if 0
    const char *file = argv[1];
    if (argc == 1)  file = "mod.o";

    int fd = open(file, O_RDONLY);
    if (fd < 0)  fail("open");

    struct stat statbuf;
    fstat(fd, &statbuf);
    off_t len = statbuf.st_size;

    void *mem = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    Elf *elf = mem;

    printf("ident: %3s\n", elf->e_ident + 1);
    printf("type:  ");
    switch (elf->e_type) {
    case ET_REL:  printf("relocatable\n"); break;
    case ET_EXEC: printf("executable\n"); break;
    case ET_DYN:  printf("dynamic\n"); break;
    default: printf("unknown\n"); break;
    }
    printf("shoff: %lu\n", elf->e_shoff);
    printf("phoff: %lu\n", elf->e_phoff);

    if (elf->e_shnum > 0) {
        printf("section headers:\n");
        Elf_Shdr *shdr = mem + elf->e_shoff;
        Elf_Shdr *shdr_string_table_section = shdr + elf->e_shstrndx;
        char *shdr_string_table = mem + shdr_string_table_section->sh_offset;

        for (int i=0; i<elf->e_shnum; i++) {
            Elf_Shdr *section = shdr + i;
            char *name = shdr_string_table + section->sh_name;
            printf("section: %s\n", name);
        }
    }
    if (elf->e_phnum > 0) {
        printf("program headers\n");
        Elf_Phdr *phdr = mem + elf->e_phoff;

        for (int i=0; i<elf->e_phnum; i++) {
            Elf_Phdr *header = phdr + i;
            printf("header: ");
            switch (header->p_type) {
            case PT_NULL: printf("unused\n"); break;
            case PT_LOAD: printf("load section\n"); break;
            case PT_DYNAMIC: printf("dynamic section\n"); break;
            case PT_INTERP: printf("program interpreter\n"); break;
            case PT_NOTE: printf("note\n"); break;
            case PT_PHDR: printf("program headers\n"); break;
            case PT_TLS: printf("thread-local storage\n"); break;
            default: printf("unknown\n"); break;
            }
        }
    }

    elf_md *e = elf_parse(mem);

    Elf_Sym *sym_tab = e->symbol_table;
    if (!sym_tab)  return 0;
    int symbol_table_count = e->symbol_table_section->sh_size / sizeof(Elf_Sym);

    printf("type bind name");
    for (int i=0; i<symbol_table_count; i++) {
        Elf_Sym *symbol = sym_tab + i;
        int type = ELF_ST_TYPE(symbol->st_info);
        int bind = ELF_ST_BIND(symbol->st_info);
        // if (bind != 1) continue;
        const char *symbol_name = e->string_table + symbol->st_name;
        printf("symbol: %i %i %s\n", type, bind, symbol_name);
    }

    printf("_DYNAMIC: %p\n", _DYNAMIC);
    printf("_GOT_   : %p\n", _GLOBAL_OFFSET_TABLE_);
#endif

    // we want to:
    // take a "libc" .so dynamic library and load it into memory
    // take a "main" dynamic executable and load + link it to libc

    elf_md *lib = elf_open("liblib.so");
    elf_md *main = elf_open("lmain");

    elf_print(lib);
    elf_print(main);

    // get needed virtual allocation size - max(ph.vaddr + ph.memsz)
    size_t lib_needed_virtual_size = 0;
    Elf_Phdr *p = lib->program_headers;
    for (int i=0; i<lib->image->e_phnum; i++) {
        if (p[i].p_type != PT_LOAD)
            continue;
        size_t max = p[i].p_vaddr + p[i].p_memsz;
        if (max > lib_needed_virtual_size)
            lib_needed_virtual_size = max;
    }

    // actually load the library into virtual memory properly
    void *lib_load = mmap(NULL, lib_needed_virtual_size,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (int i=0; i<lib->image->e_phnum; i++) {
        if (p[i].p_type != PT_LOAD)
            continue;
        memcpy(lib_load + p[i].p_vaddr, lib->mem + p[i].p_offset, p[i].p_filesz);
        // memset the rest to 0 if filesz < memsz
    }

    // get some useful things from the DYNAMIC section
    Elf_Dyn *lib_dyn_rel  = elf_find_dyn(lib, DT_JMPREL);
    Elf_Dyn *lib_dyn_sym  = elf_find_dyn(lib, DT_SYMTAB);
    Elf_Dyn *lib_dyn_str  = elf_find_dyn(lib, DT_STRTAB);
    Elf_Dyn *lib_dyn_got  = elf_find_dyn(lib, DT_PLTGOT);
    Elf_Dyn *lib_dyn_relsz = elf_find_dyn(lib, DT_PLTRELSZ);

    Elf_Rela *lib_rel = lib_load + lib_dyn_rel->d_un.d_ptr;
    Elf_Sym *lib_sym  = lib_load + lib_dyn_sym->d_un.d_ptr;
    char *lib_str     = lib_load + lib_dyn_str->d_un.d_ptr;
    Elf_Addr *lib_got = lib_load + lib_dyn_got->d_un.d_ptr;
    size_t lib_relsz  = lib_dyn_relsz->d_un.d_val;

    printf("lib load base: %p\n", lib_load);
    printf("lib dynsym   : %p\n", lib_sym);
    printf("lib pltgot   : %p\n", lib_got);
    printf("lib dynstr   : %p\n", lib_str);
    printf("lib dynrel   : %p\n", lib_rel);
    printf("lib relsz    : %zu\n", lib_relsz);

    int lib_relcnt = lib_relsz / sizeof(Elf_Rela);
    printf("lib relcnt   : %i\n", lib_relcnt);
    
    // take a look at the relocations we have
    for (int i=0; i<lib_relcnt; i++) {
        Elf_Rela *rel = lib_rel + i;
        int type = ELF64_R_TYPE(rel->r_info);

        int symix = ELF64_R_SYM(rel->r_info);
        Elf_Sym *sym = lib_sym + symix;

        char *sym_name = lib_str + sym->st_name;
        printf("relocation: type: %i, symbol: '%s'\n", type, sym_name);

        printf("  r_offset: %zx\n", rel->r_offset);
        printf("  r_addend: %zi\n", rel->r_addend);
        printf("  st_value: %zx\n", sym->st_value);
    }
}

