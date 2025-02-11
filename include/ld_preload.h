#pragma once

#include <stddef.h>

typedef struct {
        char **libs;
        size_t count;
        size_t capacity;
} ld_preload_list;

ld_preload_list *init_ld_preload_list(void);
void free_ld_preload_list(ld_preload_list *list);

int add_library(ld_preload_list *list, const char *lib);
int ld_preload_list_set_env(const ld_preload_list *list, const char *dir);

void print_libraries(const ld_preload_list *list);
