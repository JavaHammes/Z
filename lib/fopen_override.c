#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter_so.h"

#define MAX_LINE_LENGTH 1024
#define DECIMAL_BASE 10

typedef FILE *(*orig_fopen_f_type)(const char *, const char *);

FILE *fopen(const char *__restrict__filename, const char *__modes) {
        static orig_fopen_f_type real_fopen = NULL;

        if (!real_fopen) {
                void *handle = dlsym(RTLD_NEXT, "fopen");
                if (!handle) {
                        (void)(fprintf(stderr, "Error in `dlsym`: %s\n",
                                       dlerror()));
                        return NULL;
                }

                union {
                        void *ptr;
                        orig_fopen_f_type func;
                } cast;

                cast.ptr = handle;
                real_fopen = cast.func;
        }

        (void)(fprintf(stderr,
                       "[HOOK] fopen called with file=\"%s\", mode=\"%s\"\n",
                       __restrict__filename, __modes));

        if (strstr(__restrict__filename, "/proc/self/status")) {
                FILE *real_status = real_fopen(__restrict__filename, __modes);
                if (!real_status) {
                        (void)(fprintf(
                            stderr,
                            "[HOOK] Unable to open real /proc/self/status\n"));
                        return NULL;
                }

                FILE *fake_status = tmpfile();
                if (!fake_status) {
                        (void)(fclose(real_status));
                        return NULL;
                }

                char line[MAX_LINE_LENGTH];
                while (fgets(line, sizeof(line), real_status) != NULL) {
                        if (strncmp(line, "TracerPid:", DECIMAL_BASE) == 0) {
                                (void)(fprintf(fake_status, "TracerPid: 0\n"));
                        } else {
                                (void)(fputs(line, fake_status));
                        }
                }

                rewind(fake_status);
                (void)(fclose(real_status));
                return fake_status;
        }

        if (strstr(__restrict__filename, "/proc/self/maps")) {
                FILE *real_maps = real_fopen(__restrict__filename, __modes);
                if (!real_maps) {
                        (void)(fprintf(
                            stderr,
                            "[HOOK] Unable to open real /proc/self/maps\n"));
                        return NULL;
                }

                FILE *fake_maps = tmpfile();
                if (!fake_maps) {
                        (void)(fclose(real_maps));
                        return NULL;
                }

                char line[MAX_LINE_LENGTH];

                while (fgets(line, sizeof(line), real_maps) != NULL) {
                        int should_filter = 0;
                        for (int i = 0; SO_FILES[i] != NULL; i++) {
                                if (strstr(line, SO_FILES[i]) != NULL) {
                                        should_filter = 1;
                                        break;
                                }
                        }

                        if (!should_filter) {
                                (void)(fputs(line, fake_maps));
                        }
                }

                rewind(fake_maps);
                (void)(fclose(real_maps));
                return fake_maps;
        }

        return real_fopen(__restrict__filename, __modes);
}
