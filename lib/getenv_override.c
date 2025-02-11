#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void zZz(void) {}

#define MAX_LINE_LENGTH 1024

typedef char *(*orig_getenv_f_type)(const char *);

static int _has_zZz(const char *lib_path) {
        void *handle = dlopen(lib_path, RTLD_NOLOAD | RTLD_NOW);
        if (!handle) {
                return 0;
        }
        void *sym = dlsym(handle, "zZz");
        dlclose(handle);
        return (sym != NULL);
}

char *getenv(const char *name) { // NOLINT
        static orig_getenv_f_type real_getenv = NULL;

        if (!real_getenv) {
                void *sym = dlsym(RTLD_NEXT, "getenv");
                if (!sym) {
                        (void)(fprintf(
                            stderr,
                            "Error in dlsym(RTLD_NEXT, \"getenv\"): %s\n",
                            dlerror()));
                        return NULL;
                }
                union {
                        void *ptr;
                        orig_getenv_f_type func;
                } cast;
                cast.ptr = sym;
                real_getenv = cast.func;
        }

        char *original_value = real_getenv(name);

        void *caller_address = __builtin_return_address(0);
        if (caller_address) {
                Dl_info info;
                if (dladdr(caller_address, &info) != 0 && info.dli_fname) {
                        if (_has_zZz(info.dli_fname)) {
                                return original_value;
                        }
                }
        }

        if (!original_value || !*original_value) {
                return original_value;
        }

        if (strcmp(name, "LD_PRELOAD") == 0) {
                char *temp = strdup(original_value);
                if (!temp) {
                        (void)(fprintf(stderr,
                                       "[HOOK] Failed to allocate memory for "
                                       "LD_PRELOAD copy.\n"));
                        return original_value; /* fallback to original */
                }

                static char sanitized_ldpreload[MAX_LINE_LENGTH];
                sanitized_ldpreload[0] = '\0';

                char *saveptr = NULL;
                char *token = strtok_r(temp, ":", &saveptr);
                while (token) {
                        if (!_has_zZz(token)) {
                                if (sanitized_ldpreload[0] != '\0') {
                                        strncat(
                                            sanitized_ldpreload, ":",
                                            MAX_LINE_LENGTH -
                                                strlen(sanitized_ldpreload) -
                                                1);
                                }
                                strncat(sanitized_ldpreload, token,
                                        MAX_LINE_LENGTH -
                                            strlen(sanitized_ldpreload) - 1);
                        }
                        token = strtok_r(NULL, ":", &saveptr);
                }
                free(temp);

                (void)(fprintf(stderr, "[HOOK] Sanitized LD_PRELOAD: '%s'\n",
                               sanitized_ldpreload));

                return sanitized_ldpreload[0] ? sanitized_ldpreload : NULL;
        }

        return original_value;
}
