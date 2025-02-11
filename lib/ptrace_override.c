#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>

void zZz(void) {}

typedef long (*orig_ptrace_f_type)(enum __ptrace_request request, ...);

long ptrace(enum __ptrace_request request, ...) {
        union {
                void *ptr;
                orig_ptrace_f_type func;
        } cast;

        cast.ptr = dlsym(RTLD_NEXT, "ptrace");
        orig_ptrace_f_type orig_ptrace = cast.func;

        (void)(fprintf(stderr, "[HOOK] Intercepted ptrace call: option=%d\n",
                       request));

        va_list args;
        va_start(args, request);

        if (request == PTRACE_TRACEME) {
                va_end(args);
                return 0;
        }

        long result = orig_ptrace(request, va_arg(args, pid_t),
                                  va_arg(args, void *), va_arg(args, void *));
        va_end(args);

        return result;
}
