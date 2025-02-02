#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter_so.h"

#define MAX_LDPRELOAD_LEN 4096

typedef char *(*orig_getenv_f_type)(const char *);

char *getenv(const char *name) {
        static orig_getenv_f_type real_getenv = NULL;

        if (!real_getenv) {
                void *handle = dlsym(RTLD_NEXT, "getenv");
                if (!handle) {
                        (void)(fprintf(stderr, "Error in `dlsym`: %s\n",
                                       dlerror()));
                        return NULL;
                }

                union {
                        void *ptr;
                        orig_getenv_f_type func;
                } cast;
                cast.ptr = handle;
                real_getenv = cast.func;
        }

        char *original_value = real_getenv(name);

        if (strcmp(name, "LD_PRELOAD") == 0) {
                if (!original_value) {
                        (void)(fprintf(stderr,
                                       "[HOOK] LD_PRELOAD is not set.\n"));
                        return NULL;
                }

                static char sanitized_ldpreload[MAX_LDPRELOAD_LEN];
                sanitized_ldpreload[0] = '\0';

                char *token = strtok(original_value, " :");
                while (token) {
                        int should_filter = 0;
                        for (int i = 0; SO_FILES[i] != NULL; i++) {
                                if (strstr(token, SO_FILES[i]) != NULL) {
                                        should_filter = 1;
                                        break;
                                }
                        }

                        if (!should_filter) {
                                if (sanitized_ldpreload[0] != '\0') {
                                        strncat(
                                            sanitized_ldpreload, ":",
                                            MAX_LDPRELOAD_LEN -
                                                strlen(sanitized_ldpreload) -
                                                1);
                                }
                                strncat(sanitized_ldpreload, token,
                                        MAX_LDPRELOAD_LEN -
                                            strlen(sanitized_ldpreload) - 1);
                        }

                        token = strtok(NULL, " :");
                }

                (void)(fprintf(stderr, "[HOOK] Sanitized LD_PRELOAD: '%s'\n",
                               sanitized_ldpreload));
                return sanitized_ldpreload[0] ? sanitized_ldpreload : NULL;
        }

        return original_value;
}
