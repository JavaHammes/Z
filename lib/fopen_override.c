#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef FILE *(*orig_fopen_f_type)(const char *, const char *);

FILE *fopen(const char *__restrict__filename, const char *__modes) {
    static orig_fopen_f_type real_fopen = NULL;

    if (!real_fopen) {
        void *handle = dlsym(RTLD_NEXT, "fopen");
        if (!handle) {
            (void)(fprintf(stderr, "Error in `dlsym`: %s\n", dlerror()));
            return NULL;
        }

        union {
            void *ptr;
            orig_fopen_f_type func;
        } cast;

        cast.ptr = handle;
        real_fopen = cast.func;
    }

    if (strstr(__restrict__filename, "/proc/self/status")) {
        FILE *fake_file = tmpfile();
        if (fake_file) {
            (void)(fprintf(fake_file, "TracerPid: 0\n"));
            rewind(fake_file);
            return fake_file;
        }
    }

    return real_fopen(__restrict__filename, __modes);
}
