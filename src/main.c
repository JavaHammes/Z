#include "debugger.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

bool file_exists(const char *filename);

int main(int argc, char **argv) {
        if (argc < 2) {
                (void)(fprintf(stderr, "Usage: %s <debug_target>\n", argv[0]));
        }

        const char *debuggee_name = argv[1];

        if (!file_exists(debuggee_name)) {
                (void)(fprintf(stderr, "Cannot find executable %s",
                               debuggee_name));
                return EXIT_FAILURE;
        }

        debugger dbg;
        init_debugger(&dbg, debuggee_name);

        if (start_debuggee(&dbg) != 0) {
                (void)(fprintf(stderr, "Failed to start debuggee.\n"));
                free_debugger(&dbg);
                return EXIT_FAILURE;
        }

        if (trace_debuggee(&dbg) != 0) {
                (void)(fprintf(stderr, "Error while tracing debuggee.\n"));
                free_debugger(&dbg);
                return EXIT_FAILURE;
        }

        free_debugger(&dbg);
        return EXIT_SUCCESS;
}

bool file_exists(const char *filename) {
        if (filename[0] == '.') {
                return false;
        }
        return access(filename, F_OK | X_OK) == 0;
}
