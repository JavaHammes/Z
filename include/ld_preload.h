#pragma once

#include <stddef.h>

typedef struct {
        char **libs;
        size_t count;
        size_t capacity;
} ld_preload_list;

ld_preload_list *ld_preload_list_init(void);
void ld_preload_list_free(ld_preload_list *list);

void ld_preload_list_print(const ld_preload_list *list);

int ld_preload_list_add(ld_preload_list *list, const char *lib);
int ld_preload_list_set_env(const ld_preload_list *list, const char *dir);
char *ld_preload_list_get_env(const ld_preload_list *list, const char *dir);
