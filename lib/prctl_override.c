#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/prctl.h>

void zZz(void) {}

#define COLOR_RESET "\033[0m"
#define COLOR_CYAN "\033[36m"

typedef int (*orig_prctl_f_type)(int option, ...);

int prctl(int option, ...) {
        union {
                void *ptr;
                orig_prctl_f_type func;
        } cast;

        cast.ptr = dlsym(RTLD_NEXT, "prctl");
        orig_prctl_f_type orig_prctl = cast.func;

        (void)(fprintf(stderr,
                       COLOR_CYAN
                       "[HOOK] Intercepted prctl call: option=%d\n" COLOR_RESET,
                       option));

        va_list args;
        va_start(args, option);

        if (option == PR_SET_DUMPABLE) {
                va_end(args);
                return orig_prctl(PR_SET_DUMPABLE, 1); // MU HA HA HAA
        }

        int result = orig_prctl(option, args);
        va_end(args);

        return result;
}
