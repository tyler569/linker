#include <stdlib.h>
#include <sys/types.h>
#include "linker/elf.h"

void fail(const char *message);

struct elf_metadata {
    void *mem;
    Elf *image;
    void *load_mem;
    void *load_base;
    void *bss_base;
    size_t file_size;

    Elf_Shdr *section_headers;

    Elf_Shdr *shdr_string_table_section;
    const char *shdr_string_table;
    Elf_Shdr *symbol_table_section;
    size_t symbol_count;
    Elf_Sym *symbol_table;

    Elf_Shdr *string_table_section;
    const char *string_table;

    Elf_Phdr *program_headers;

    Elf_Dyn *dynamic_table;
    size_t dynamic_count;
};
typedef struct elf_metadata elf_md;

void elf_print(elf_md *e);

/*
 * Always returns the first matching header, if you need multiple (i.e. all
 * the PT_LOADs, just iterate yourself.)
 */
Elf_Phdr *elf_find_phdr(elf_md *e, int p_type);
Elf_Dyn *elf_find_dyn(elf_md *e, int d_tag);
Elf_Shdr *elf_find_section(elf_md *e, const char *name);
Elf_Sym *elf_find_symbol(elf_md *e, const char *name);

const char *elf_symbol_name(elf_md *e, Elf_Sym *sym);

elf_md *elf_parse(void *memory);
elf_md *elf_open(const char *name);
