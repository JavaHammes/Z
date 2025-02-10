#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ld_preload.h"
#include "ui.h"

#define INITIAL_CAPACITY 4

ld_preload_list *ld_preload_list_init(void) {
        ld_preload_list *list = malloc(sizeof(ld_preload_list));
        if (!list) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to allocate ld_preload_list: %s\n" COLOR_RESET,
                    strerror(errno)));
                return NULL;
        }
        list->libs = malloc(INITIAL_CAPACITY * sizeof(char *));
        if (!list->libs) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to allocate initial libs array: %s\n" COLOR_RESET,
                    strerror(errno)));
                free(list);
                return NULL;
        }
        list->count = 0;
        list->capacity = INITIAL_CAPACITY;
        return list;
}

void ld_preload_list_free(ld_preload_list *list) {
        if (!list) {
                return;
        }

        for (size_t i = 0; i < list->count; i++) {
                free(list->libs[i]);
        }
        free(list->libs);
        free(list);
}

int ld_preload_list_add(ld_preload_list *list, const char *lib) {
        if (!list || !lib) {
                return -1;
        }

        for (size_t i = 0; i < list->count; i++) {
                if (strcmp(list->libs[i], lib) == 0) {
                        return 0;
                }
        }

        if (access(lib, R_OK) == -1) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Library '%s' is not accessible: %s\n" COLOR_RESET,
                    lib, strerror(errno)));
                return -1;
        }

        if (list->count == list->capacity) {
                size_t new_capacity = list->capacity * 2;
                char **new_libs =
                    realloc(list->libs, new_capacity * sizeof(char *));
                if (!new_libs) {
                        (void)(fprintf(stderr,
                                       COLOR_RED "Failed to expand ld_preload "
                                                 "list: %s\n" COLOR_RESET,
                                       strerror(errno)));
                        return -1;
                }
                list->libs = new_libs;
                list->capacity = new_capacity;
        }

        list->libs[list->count] = strdup(lib);
        if (!list->libs[list->count]) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to duplicate library string: %s\n" COLOR_RESET,
                    strerror(errno)));
                return -1;
        }
        list->count++;
        return 0;
}

char *ld_preload_list_get_env(const ld_preload_list *list, const char *dir) {
        if (!list || list->count == 0) {
                return NULL;
        }

        size_t total_length = 0;
        for (size_t i = 0; i < list->count; i++) {
                if (dir) {
                        total_length += strlen(dir) + 1;
                }
                total_length += strlen(list->libs[i]);
                if (i < list->count - 1) {
                        total_length++;
                }
        }
        total_length++;

        char *env_str = malloc(total_length);
        if (!env_str) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to allocate LD_PRELOAD env "
                                         "string: %s\n" COLOR_RESET,
                               strerror(errno)));
                return NULL;
        }

        env_str[0] = '\0';
        for (size_t i = 0; i < list->count; i++) {
                if (i > 0) {
                        strcat(env_str, ":");
                }
                if (dir) {
                        strcat(env_str, dir);
                        strcat(env_str, "/");
                }
                strcat(env_str, list->libs[i]);
        }
        return env_str;
}

int ld_preload_list_set_env(const ld_preload_list *list, const char *dir) {
        char *env_value = ld_preload_list_get_env(list, dir);
        if (!env_value) {
                return -1;
        }

        int result = setenv("LD_PRELOAD", env_value, 1);
        if (result == -1) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Failed to set LD_PRELOAD: %s\n" COLOR_RESET,
                               strerror(errno)));
        }
        free(env_value);
        return result;
}

void ld_preload_list_print(const ld_preload_list *list) {
        if (!list) {
                return;
        }
        printf("LD_PRELOAD libraries (%zu):\n", list->count);
        for (size_t i = 0; i < list->count; i++) {
                printf("  %s\n", list->libs[i]);
        }
}
