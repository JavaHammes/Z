#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void zZz(void) {}

#define MAX_LIBS 128
#define MAX_LINE_LENGTH 1024
#define DECIMAL_BASE 10

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_CYAN "\033[36m"

static char *ld_preload_libs[MAX_LIBS] = {NULL};
typedef FILE *(*orig_fopen_f_type)(const char *, const char *);

static int _has_zZz(const char *lib_path) {
        void *handle = dlopen(lib_path, RTLD_NOLOAD | RTLD_NOW);
        if (!handle) {
                return 0;
        }
        void *sym = dlsym(handle, "zZz");
        dlclose(handle);
        return (sym != NULL);
}

static void parse_ld_preload(void) {
        for (int j = 0; j < MAX_LIBS; j++) {
                if (ld_preload_libs[j] != NULL) {
                        free(ld_preload_libs[j]);
                        ld_preload_libs[j] = NULL;
                }
        }

        const char *ld_preload = getenv("LD_PRELOAD");
        if (!ld_preload || !*ld_preload) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "[HOOK] LD_PRELOAD is not set or empty.\n" COLOR_RESET));
                return;
        }

        char *temp = strdup(ld_preload);
        if (!temp) {
                (void)(fprintf(stderr,
                               COLOR_RED "[HOOK] Failed to allocate memory for "
                                         "LD_PRELOAD copy.\n" COLOR_RESET));
                return;
        }

        int i = 0;
        char *saveptr = NULL;
        for (char *token = strtok_r(temp, ":", &saveptr);
             token != NULL && i < MAX_LIBS - 1;
             token = strtok_r(NULL, ":", &saveptr)) {
                if (_has_zZz(token)) {
                        ld_preload_libs[i++] = strdup(token);
                }
        }
        free(temp);
}

FILE *fopen(const char *__restrict__filename, const char *__modes) { // NOLINT
        static orig_fopen_f_type real_fopen = NULL;

        if (!real_fopen) {
                void *handle = dlsym(RTLD_NEXT, "fopen");
                if (!handle) {
                        (void)(fprintf(
                            stderr,
                            COLOR_RED
                            "[HOOK] Error in dlsym for fopen: %s\n" COLOR_RESET,
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

        parse_ld_preload();

        (void)(fprintf(
            stderr,
            COLOR_CYAN
            "[HOOK] fopen called with file=\"%s\", mode=\"%s\"\n" COLOR_RESET,
            __restrict__filename, __modes));

        if (strstr(__restrict__filename, "/proc/self/status")) {
                FILE *real_status = real_fopen(__restrict__filename, __modes);
                if (!real_status) {
                        (void)(fprintf(stderr, COLOR_RED
                                       "[HOOK] Unable to open real "
                                       "/proc/self/status\n" COLOR_RESET));
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
                        (void)(fprintf(stderr, COLOR_RED
                                       "[HOOK] Unable to open real "
                                       "/proc/self/maps\n" COLOR_RESET));
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
                        for (int i = 0; ld_preload_libs[i] != NULL; i++) {
                                if (strstr(line, ld_preload_libs[i]) != NULL) {
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

__attribute__((destructor)) static void free_ld_preload_libs(void) {
        for (int i = 0; i < MAX_LIBS; i++) {
                if (ld_preload_libs[i]) {
                        free(ld_preload_libs[i]);
                        ld_preload_libs[i] = NULL;
                }
        }
}
