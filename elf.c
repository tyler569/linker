
#include <ng/basic.h>
#include <ng/elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h> 

#if defined(__kernel__) && defined(__nightingale__)
#include <ng/multiboot2.h>
#include <ng/panic.h>
#include <ng/print.h>
#include <ng/string.h>
#include <ng/vmm.h>
#elif __STDC_HOSTED__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#ifdef __kernel__
#define fail() panic()
#else
#define fail() exit(EXIT_FAILURE)
#endif


struct elfinfo ngk_elfinfo;

void elf_debugprint(Elf *elf) {
        int bits = elf_verify(elf);
        if (bits == 0) {
                printf("invalid elf\n");
                return;
        }
        Elf *hdr = elf;
        printf("elf64:\n");
        printf("  entrypoint: %#lx\n", hdr->e_entry);
        printf("  phdr      : %#lx\n", hdr->e_phoff);
        printf("  phnum     : %#x\n", hdr->e_phnum);

        char *phdr_l = ((char *)hdr) + hdr->e_phoff;
        Elf_Phdr *phdr = (Elf_Phdr *)phdr_l; 
        for (int i = 0; i < hdr->e_phnum; i++) {
                if (phdr[i].p_type != PT_LOAD)
                        continue;

                printf(
                    "    load file:%#010zx+%#06zx -> %#010zx %s%s%s\n",
                    phdr[i].p_offset, phdr[i].p_memsz, phdr[i].p_vaddr,

                    phdr[i].p_flags & PF_R ? "r" : "-",
                    phdr[i].p_flags & PF_W ? "w" : "-",
                    phdr[i].p_flags & PF_X ? "x" : "-");
        }
}

const char elf64_header_example[7] = {
        0x7F, 'E', 'L', 'F', ELF64, ELFLE, ELFVERSION,
};

const char elf32_header_example[7] = {
        0x7F, 'E', 'L', 'F', ELF32, ELFLE, ELFVERSION,
};

int elf_verify(Elf *elf) {
        if (memcmp(elf, elf64_header_example, 7) == 0) {
                return 64;
        } else if (memcmp(elf, elf32_header_example, 7) == 0) {
                return 32;
        } else {
                return 0;
        }
}

#ifdef __kernel__
void init_section(void *dst_vaddr, size_t len) {
        uintptr_t bot = round_down((uintptr_t)dst_vaddr, 0x1000);
        uintptr_t top = round_up((uintptr_t)dst_vaddr + len, 0x1000);

        for (uintptr_t p = bot; p <= top; p += 0x1000)
                vmm_create_unbacked(p, PAGE_USERMODE | PAGE_WRITEABLE);
}

void load_section(void *dst_vaddr, void *src_vaddr, size_t flen, size_t mlen) {
        memcpy(dst_vaddr, src_vaddr, flen);

        // BSS is specified by having p_memsz > p_filesz
        // you are expected to zero the extra space
        if (mlen > flen) {
                memset((char *)dst_vaddr + flen, 0, mlen - flen);
        }
}

int elf_load(Elf *elf) {
        int bits = elf_verify(elf);
        if (bits == 0) {
                printf("invalid elf\n");
                return -1;
        }
        char *phdr_l = ((char *)elf) + elf->e_phoff;
        Elf_Phdr *phdr = (Elf_Phdr *)phdr_l;

        for (int i = 0; i < elf->e_phnum; i++) {
                Elf_Phdr *sec = &phdr[i];
                if (sec->p_type != PT_LOAD)
                        continue;
                void *section = elf_at(elf, sec->p_offset);

                init_section((void *)sec->p_vaddr, sec->p_memsz);
                load_section((void *)sec->p_vaddr, section,
                             sec->p_filesz, sec->p_memsz);
        }
        return 0;
}
#endif

void *elf_at(Elf *elf, size_t offset) {
        return ((char *)elf) + offset;
}

Elf_Shdr *elf_get_sec(Elf *elf, const char *name) {
        Elf_Shdr *shdr = elf_at(elf, elf->e_shoff);
        char *str_tab = elf_at(elf, shdr[elf->e_shstrndx].sh_offset);

        Elf_Shdr *sec = NULL;

        for (int i=0; i<elf->e_shnum; i++) {
                if (!shdr[i].sh_size) {
                        continue;
                }
                if (strcmp(&str_tab[shdr[i].sh_name], name) == 0) {
                        sec = &shdr[i];
                }
        }

        return sec;
}

struct elfinfo elf_info(Elf *elf) {
        if (elf_verify(elf) == 0) {
                printf("invalid elf passed to elf_info\n");
                fail();
        }

        struct elfinfo ret = {0};

        ret.elf = elf;
        ret.shdr_count = elf->e_shnum;
        ret.shstrndx = elf->e_shstrndx;

        ret.shdr = elf_at(elf, elf->e_shoff);
        ret.shstrtab = elf_at(elf, ret.shdr[elf->e_shstrndx].sh_offset);

        ret.symtab = elf_get_sec(elf, ".symtab");
        ret.strtab = elf_get_sec(elf, ".strtab");

        return ret;
}

void *ei_sec(struct elfinfo *elf, Elf_Shdr *shdr) {
        if (elf->elf) {
                return (char *)elf->elf + shdr->sh_offset;
        }
#ifdef __kernel__
        else {
                return (char *)shdr->sh_addr + VMM_VIRTUAL_OFFSET;
        }
#else
        else {
                printf("invalid elfinfo - no ->elf\n");
                fail();
        }
#endif
}

void elf_print_syms(struct elfinfo *ei) {
        Elf_Sym *sym = ei_sec(ei, ei->symtab);
        char *str = ei_sec(ei, ei->strtab);

        for (int i=0; i<ei->symtab->sh_size / sizeof(Elf_Sym); i++) {
                if (*(str + sym[i].st_name)) {
                        printf("%s: %lx\n",
                                str + sym[i].st_name, sym[i].st_value);
                }
        }
}

Elf_Sym *elf_get_sym_p(struct elfinfo *ei, const char *name) {
        Elf_Sym *sym = ei_sec(ei, ei->symtab);
        char *str = ei_sec(ei, ei->strtab);

        Elf_Sym *result = NULL;

        for (int i=0; i<ei->symtab->sh_size / sizeof(Elf_Sym); i++) {
                if (strcmp(str + sym[i].st_name, name) == 0) {
                        result = &sym[i];
                        break;
                }
        }
        
        return result;
}

Elf_Sym *elf_get_sym_by_ix(struct elfinfo *ei, long symindex) {
        Elf_Sym *sym = ei_sec(ei, ei->symtab);

        return &sym[symindex];
}

size_t elf_get_sym_off(struct elfinfo *ei, const char *name) {
        Elf_Shdr *shdr = ei->shdr;
        Elf_Sym *sym = elf_get_sym_p(ei, name);

        size_t value = 0;
        if (sym) {
                value += sym->st_value;
                value += shdr[sym->st_shndx].sh_offset;
        }
        return value;
}

void elf64_print_rels_in_section(struct elfinfo *ei, Elf_Shdr *shdr) {
        Elf64_Rela *rela = ei_sec(ei, shdr);

        Elf_Shdr *strtab = ei->strtab;
        char *str = ei_sec(ei, ei->strtab);

        for (int i=0; i<shdr->sh_size / sizeof(Elf64_Rela); i++) {
                long symindex = ELF64_R_SYM(rela[i].r_info);
                long reltype = ELF64_R_TYPE(rela[i].r_info);

                printf("%lx %lx %lx %lx\n", rela[i].r_offset,
                        symindex, reltype, rela[i].r_addend);

                Elf_Sym *sym = elf_get_sym_by_ix(ei, symindex);
                if (str[sym->st_name])
                        printf(" %li is %s\n", symindex, &str[sym->st_name]);

                printf("value : %p\n", (void *)(sym->st_value));
        }
}

void elf_print_rels(struct elfinfo *ei) {
        Elf_Shdr *shdr = ei->shdr;
        Elf_Shdr *strtab = ei->strtab;
        char *str = ei_sec(ei, ei->strtab);

        for (int i=0; i<ei->shdr_count; i++) {
                if (shdr[i].sh_type != SHT_RELA) {
                        continue;
                }
                elf64_print_rels_in_section(ei, &shdr[i]);
        }
}


void elf_resolve_symbols(struct elfinfo *master, struct elfinfo *child) {
        Elf_Shdr *shdr = child->shdr;
        Elf_Shdr *symtab = child->symtab;
        Elf_Shdr *strtab = child->strtab;

        Elf_Sym *sym = ei_sec(child, symtab);
        char *str = ei_sec(child, strtab);

        for (int i=0; i<symtab->sh_size / sizeof(Elf_Sym); i++) {
                int type = ELF_ST_TYPE(sym[i].st_info);
                if (type == STT_FILE)
                        continue;

                if (sym[i].st_shndx == 0 || sym[i].st_shndx >= 0xFF00) {
                        Elf_Sym *master_sym = elf_get_sym_p(master,
                                                        &str[sym[i].st_name]);
                        if (!master_sym) {
                                printf("symbol failed to resolve: %s\n",
                                                &str[sym[i].st_name]);
                                continue;
                        }
                        // printf("symbol resolved: %s -> %lx\n",
                        //                 &str[sym[i].st_name],
                        //                 master_sym->st_value);

                        sym[i].st_value = master_sym->st_value;
                }
        }
}

const char *rel_type_names[] = {
        [R_X86_64_NONE]  = "R_X86_64_NONE",
        [R_X86_64_64]    = "R_X86_64_64",
        [R_X86_64_32]    = "R_X86_64_32",
        [R_X86_64_32S]   = "R_X86_64_32S",
        [R_X86_64_PC32]  = "R_X86_64_PC32",
        [R_X86_64_PLT32] = "R_X86_64_PLT32",
};

const char *rel32_type_names[] = {
        [R_386_32]       = "R_386_32",
        [R_386_PC32]     = "R_386_PC32",
};

#if X86_64
int perform_relocations_in_section(struct elfinfo *ei, Elf_Shdr *rshdr,
                                   uintptr_t new_base) {
        Elf_Shdr *shdr = ei->shdr;

        Elf64_Rela *rela = ei_sec(ei, rshdr);
        char *str_tab = ei->shstrtab;

        // printf(" (section %s)\n", &str_tab[rshdr->sh_name]);

        Elf_Shdr *link_shdr = &shdr[rshdr->sh_info];
        // printf("  (links to %s)\n", &str_tab[link_shdr->sh_name]);

        Elf_Shdr *strtab = ei->strtab;
        Elf_Shdr *symtab = ei->symtab;
        char *str = ei_sec(ei, strtab);
        Elf_Sym *rsym = ei_sec(ei, symtab);

        for (int i=0; i<rshdr->sh_size / sizeof(Elf64_Rela); i++) {
                // unsigned long loc = link_shdr->sh_addr + rela[i].r_offset;

                int rel_type = ELF64_R_TYPE(rela[i].r_info);
                int symindex = ELF64_R_SYM(rela[i].r_info);
                Elf_Sym *sym = &rsym[symindex];

                unsigned long loc = rela[i].r_offset;
                loc += link_shdr->sh_offset;

                // inside the kernel, the file will already be loaded to it's
                // final location and we can perform the relocations actually
                // in place, and this becomes redundant.
                unsigned long i_loc = loc + new_base;
                unsigned long p_loc = loc + (uintptr_t)ei->elf;

                unsigned long value;
                value = shdr[sym->st_shndx].sh_offset;
                value += sym->st_value;
                value += rela[i].r_addend;

                // suuuuuuuuuuuuuuper jank
                if (value < 0x100000) {
                        value += new_base;
                }

#if 0
                if (rel_type_names[rel_type] && sym->st_name != 0) {
                        printf("(%s) ", &str[sym->st_name]);
                        printf("relocating: %s at %lx with v:%lx\n",
                                        rel_type_names[rel_type], i_loc, value);
                }
#endif

                // TODO: check the location is empty and that
                // there was no overflow
                switch(ELF64_R_TYPE(rela[i].r_info)) {
                case R_X86_64_NONE:
                        break;
                case R_X86_64_64:
                        *(uint64_t *)p_loc = value;
                        break;
                case R_X86_64_32:
                        *(uint32_t *)p_loc = value;
                        break;
                case R_X86_64_32S:
                        *(int32_t *)p_loc = value;
                        break;
                case R_X86_64_PC32:
                case R_X86_64_PLT32:
                        value -= (uint64_t)i_loc;
                        // printf("  - actually placing %lx\n", (uint32_t)value);
                        *(uint32_t *)p_loc = value;
                        break;
                default:
                        printf("invalid relocation type: %li\n",
                                        ELF64_R_TYPE(rela[i].r_info));
                }
        }

        return 0;
}
#elif I686
int perform_relocations_in_section(struct elfinfo *ei, Elf_Shdr *rshdr,
                                   uintptr_t new_base) {
        Elf_Shdr *shdr = ei->shdr;

        Elf32_Rel *rel = ei_sec(ei, rshdr);
        char *str_tab = ei->shstrtab;

        printf(" (section %s)\n", &str_tab[rshdr->sh_name]);

        Elf_Shdr *link_shdr = &shdr[rshdr->sh_info];
        printf("  (links to %s)\n", &str_tab[link_shdr->sh_name]);

        Elf_Shdr *strtab = ei->strtab;
        Elf_Shdr *symtab = ei->symtab;
        char *str = ei_sec(ei, strtab);
        Elf_Sym *rsym = ei_sec(ei, symtab);

        for (int i=0; i<rshdr->sh_size / sizeof(Elf32_Rel); i++) {
                int rel_type = ELF32_R_TYPE(rel[i].r_info);
                int symindex = ELF32_R_SYM(rel[i].r_info);
                Elf_Sym *sym = &rsym[symindex];

                char *loc = (char *)rel[i].r_offset;
                loc += link_shdr->sh_offset;
                loc += (size_t)ei->elf;

                unsigned long value;
                // value = shdr[sym->st_shndx].sh_offset; // ?
                value = sym->st_value;
                
                // suuuuuuuuuuuuuuper jank
                if (value < 0x100000) {
                        value += new_base;
                }

                if (rel32_type_names[rel_type] && sym->st_name != 0) {
                        printf("(%s) ", &str[sym->st_name]);
                        printf("relocating: %s at %lx with v:%lx\n",
                                        rel32_type_names[rel_type], loc, value);
                }

                switch(rel_type) {
                case R_386_32:
                        *loc += value;
                        break;
                case R_386_PC32:
                        *loc += value - (uint32_t)loc;
                        break;
                default:
                        printf("invalid relocation type: %li\n",
                                        ELF32_R_TYPE(rel[i].r_info));
                }
        }

        return 0;
        
}
#endif

int elf_relocate_object(struct elfinfo *ei, uintptr_t new_base) {
        /*
         * This isn't done!
         *
         * This should place section headers at locations first
         * probably using the ->sh_addr fields so that I can perform
         * relocations more simply.
         *
         * Currently, this does not make any allowance for the BSS section at all!!!!
         *
         */

#if 0
        // TODO
        for (int i=0; i<ei->shdr_count; i++) {
                if (header has ALLOC flag) {
                        find a place to put the section;
                        set ->sh_paddr (?);
                }
        }

        // TODO: once this is done
        // make the relocations above use the addr field of the section
        // and not the offset in the file
        //
        // double TODO:
        // once that is done make a load_elf_by_sections() that loads an
        // ELF with addrs in its sections into memory (OR just make a program
        // header that accurately reflects the needed loding information)
#endif

        for (int i=0; i<ei->shdr_count; i++) {
                if (ei->shdr[i].sh_type != SHT_RELA &&
                    ei->shdr[i].sh_type != SHT_REL) 
                        continue;

                // inside relocation shdr
                perform_relocations_in_section(ei, &ei->shdr[i], new_base);
        }
        return 0;
}

