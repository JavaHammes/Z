#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "symtab.h"
#include "ui.h"

bool read_elf_symtab(const char *elf_path, // NOLINT
                     elf_symtab *symtab_struct) {
        if (elf_path == NULL || symtab_struct == NULL) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Invalid arguments to read_elf_symtab.\n" COLOR_RESET));
                return false;
        }

        int fd = open(elf_path, O_RDONLY);
        if (fd < 0) {
                perror("open ELF file");
                return false;
        }

        Elf64_Ehdr ehdr;
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
                perror("read ELF header");
                close(fd);
                return false;
        }

        if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
                (void)(fprintf(
                    stderr, COLOR_RED "Not a valid ELF file: %s\n" COLOR_RESET,
                    elf_path));
                close(fd);
                return false;
        }

        if (lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET) == -1) {
                perror("lseek to section headers");
                close(fd);
                return false;
        }

        Elf64_Shdr *shdrs = malloc((size_t)(ehdr.e_shentsize * ehdr.e_shnum));
        if (!shdrs) {
                perror("malloc for section headers");
                close(fd);
                return false;
        }

        if (read(fd, shdrs, (size_t)(ehdr.e_shentsize * ehdr.e_shnum)) !=
            (ssize_t)(ehdr.e_shentsize * ehdr.e_shnum)) {
                perror("read section headers");
                free(shdrs);
                close(fd);
                return false;
        }

        Elf64_Shdr sh_strtab = shdrs[ehdr.e_shstrndx];
        char *shstrtab = malloc(sh_strtab.sh_size);
        if (!shstrtab) {
                perror("malloc for shstrtab");
                free(shdrs);
                close(fd);
                return false;
        }

        if (lseek(fd, (off_t)sh_strtab.sh_offset, SEEK_SET) == -1) {
                perror("lseek to shstrtab");
                free(shstrtab);
                free(shdrs);
                close(fd);
                return false;
        }

        if (read(fd, shstrtab, sh_strtab.sh_size) !=
            (ssize_t)sh_strtab.sh_size) {
                perror("read shstrtab");
                free(shstrtab);
                free(shdrs);
                close(fd);
                return false;
        }

        symtab_struct->entries = NULL;
        symtab_struct->num_entries = 0;

        for (int i = 0; i < ehdr.e_shnum; i++) {
                const char *section_name = shstrtab + shdrs[i].sh_name;

                if (strcmp(section_name, ".symtab") != 0 &&
                    strcmp(section_name, ".dynsym") != 0) {
                        continue;
                }

                Elf64_Sym *current_symtab = malloc(shdrs[i].sh_size);
                if (!current_symtab) {
                        perror("malloc for symtab");
                        continue;
                }

                if (lseek(fd, (off_t)shdrs[i].sh_offset, SEEK_SET) == -1) {
                        perror("lseek to symtab");
                        free(current_symtab);
                        continue;
                }

                if (read(fd, current_symtab, shdrs[i].sh_size) !=
                    (ssize_t)shdrs[i].sh_size) {
                        perror("read symtab");
                        free(current_symtab);
                        continue;
                }

                size_t current_num_symbols =
                    shdrs[i].sh_size / sizeof(Elf64_Sym);

                Elf64_Shdr strtab_shdr = shdrs[shdrs[i].sh_link];
                char *current_strtab = malloc(strtab_shdr.sh_size);
                if (!current_strtab) {
                        perror("malloc for strtab");
                        free(current_symtab);
                        continue;
                }

                if (lseek(fd, (off_t)strtab_shdr.sh_offset, SEEK_SET) == -1) {
                        perror("lseek to strtab");
                        free(current_strtab);
                        free(current_symtab);
                        continue;
                }

                if (read(fd, current_strtab, strtab_shdr.sh_size) !=
                    (ssize_t)strtab_shdr.sh_size) {
                        perror("read strtab");
                        free(current_strtab);
                        free(current_symtab);
                        continue;
                }

                elf_symtab_entry *new_entries = realloc(
                    symtab_struct->entries, (symtab_struct->num_entries + 1) *
                                                sizeof(elf_symtab_entry));
                if (!new_entries) {
                        perror("realloc for symtab entries");
                        free(current_strtab);
                        free(current_symtab);
                        continue;
                }

                symtab_struct->entries = new_entries;
                symtab_struct->entries[symtab_struct->num_entries].symtab =
                    current_symtab;
                symtab_struct->entries[symtab_struct->num_entries].num_symbols =
                    current_num_symbols;
                symtab_struct->entries[symtab_struct->num_entries].strtab =
                    current_strtab;
                symtab_struct->num_entries += 1;
        }

        free(shstrtab);
        free(shdrs);
        close(fd);

        if (symtab_struct->entries == NULL || symtab_struct->num_entries == 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "No symbol tables found in ELF file: %s\n" COLOR_RESET,
                    elf_path));
                return false;
        }

        return true;
}
