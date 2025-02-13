#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ld_preload.h"
#include "ui.h"

static void _alloc_new_capacity(ld_preload_list *list) {
        size_t new_capacity = (list->capacity == 0) ? 4 : list->capacity * 2;

        char **new_libs =
            (char **)realloc((void *)list->libs, new_capacity * sizeof(char *));
        if (!new_libs) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to expand ld_preload list: %s\n" COLOR_RESET,
                    strerror(errno)));
                exit(EXIT_FAILURE);
        }

        list->libs = new_libs;
        list->capacity = new_capacity;
}

static char *_ld_preload_list_get_env(const ld_preload_list *list,
                                      const char *dir) {
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
                        total_length += 1;
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
                        strncat(env_str, ":",
                                total_length - strlen(env_str) - 1);
                }
                if (dir) {
                        strncat(env_str, dir,
                                total_length - strlen(env_str) - 1);
                        strncat(env_str, "/",
                                total_length - strlen(env_str) - 1);
                }
                strncat(env_str, list->libs[i],
                        total_length - strlen(env_str) - 1);
        }

        return env_str;
}

ld_preload_list *init_ld_preload_list(void) {
        ld_preload_list *list = malloc(sizeof(ld_preload_list));
        if (!list) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to allocate ld_preload_list: %s\n" COLOR_RESET,
                    strerror(errno)));
                return NULL;
        }

        list->libs = NULL;
        list->count = 0;
        list->capacity = 0;
        return list;
}

void free_ld_preload_list(ld_preload_list *list) {
        if (!list) {
                return;
        }

        for (size_t i = 0; i < list->count; i++) {
                free(list->libs[i]);
        }

        free((void *)list->libs);
        free(list);
}

int add_library(ld_preload_list *list, const char *lib) {
        if (list->count == list->capacity) {
                _alloc_new_capacity(list);
        }

        for (size_t i = 0; i < list->count; i++) {
                if (strcmp(list->libs[i], lib) == 0) {
                        return EXIT_FAILURE;
                }
        }

        const char *lib_to_add = lib;
        char resolved_path[PATH_MAX];

        if (access(lib, F_OK | R_OK) != 0) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Cannot find preload library: %s\n" COLOR_RESET,
                               lib));
                return EXIT_FAILURE;
        }

        if (strchr(lib, '/') == NULL) {
                (void)(snprintf(resolved_path, sizeof(resolved_path), "./%s",
                                lib));
                if (access(resolved_path, F_OK | R_OK) != 0) {
                        (void)(fprintf(
                            stderr,
                            COLOR_RED
                            "Cannot find preload library: %s\n" COLOR_RESET,
                            lib));
                        return EXIT_FAILURE;
                }
                lib_to_add = resolved_path;
        }

        list->libs[list->count] = strdup(lib_to_add);
        if (!list->libs[list->count]) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to duplicate library string: %s\n" COLOR_RESET,
                    strerror(errno)));
                return EXIT_FAILURE;
        }

        list->count++;
        return EXIT_SUCCESS;
}

int ld_preload_list_set_env(const ld_preload_list *list, const char *dir) {
        char *env_value = _ld_preload_list_get_env(list, dir);
        if (!env_value) {
                return EXIT_FAILURE;
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

void print_libraries(const ld_preload_list *list) {
        if (!list) {
                return;
        }

        printf(COLOR_CYAN "LD_PRELOAD libraries (%zu):\n", list->count);
        for (size_t i = 0; i < list->count; i++) {
                printf(COLOR_GREEN "  %s\n" COLOR_RESET, list->libs[i]);
        }
        printf(COLOR_RESET);
}
