#include <elf.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct {
        Elf64_Sym *symtab;
        size_t num_symbols;
        char *strtab;
} elf_symtab_entry;

typedef struct {
        elf_symtab_entry *entries;
        size_t num_entries;
} elf_symtab;

bool read_elf_symtab(const char *elf_path, elf_symtab *symtab_struct);
