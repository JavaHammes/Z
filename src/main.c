#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "debugger.h"

bool is_relative_path(const char *filename) { return filename[0] == '.'; }

bool file_exists(const char *filename) {
        return access(filename, F_OK | X_OK) == 0;
}

int main(int argc, char **argv) {
        if (argc < 2) {
                (void)(fprintf(stderr, "Usage: %s <debug_target>\n", argv[0]));
                return EXIT_FAILURE;
        }

        const char *debuggee_name = argv[1];

        if (is_relative_path(debuggee_name)) {
                (void)(fprintf(stderr, "No relative paths allowed %s\n",
                               debuggee_name));
                return EXIT_FAILURE;
        }

        if (!file_exists(debuggee_name)) {
                (void)(fprintf(stderr, "Cannot find executable %s\n",
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
