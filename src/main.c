#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "debugger.h"
#include "ui.h"

static bool _is_relative_path(const char *filename) {
        return filename[0] == '.';
}

static bool _file_exists(const char *filename) {
        return access(filename, F_OK | R_OK) == 0;
}

static int _process_ld_preload_args(debugger *dbg, int argc, char **argv) {
    if (argc > 2) {
        for (int i = 2; i < argc; i++) {
            const char *lib_path = argv[i];

            if (!_file_exists(lib_path)) {
                (void)(fprintf(stderr, COLOR_RED "Cannot find preload library: %s\n" COLOR_RESET, lib_path));
                free_debugger(dbg);
                return EXIT_FAILURE;
            }

            if (ld_preload_list_add(dbg->preload_list, lib_path) != 0) {
                (void)(fprintf(stderr, COLOR_RED "Failed to add preload library: %s\n" COLOR_RESET, lib_path));
                free_debugger(dbg);
                return EXIT_FAILURE;
            }
        }
    }
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
        if (argc < 2) {
                (void)(fprintf(stderr,
                        COLOR_RED
                        "Usage: %s <debug_target> [ld_preload_library1 "
                        "[ld_preload_library2 ...]]\n" COLOR_RESET,
                        argv[0]));
                return EXIT_FAILURE;
        }

        const char *debuggee_name = argv[1];

        if (_is_relative_path(debuggee_name)) {
                (void)(fprintf(stderr,
                        COLOR_RED "No relative paths allowed for debug target: "
                                  "%s\n" COLOR_RESET,
                        debuggee_name));
                return EXIT_FAILURE;
        }

        if (!_file_exists(debuggee_name)) {
                (void)(fprintf(stderr,
                        COLOR_RED "Cannot find executable: %s\n" COLOR_RESET,
                        debuggee_name));
                return EXIT_FAILURE;
        }

        debugger dbg;
        init_debugger(&dbg, debuggee_name);

        if (_process_ld_preload_args(&dbg, argc, argv) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
        }

        if (start_debuggee(&dbg) != 0) {
                (void)(fprintf(stderr,
                        COLOR_RED "Failed to start debuggee.\n" COLOR_RESET));
                free_debugger(&dbg);
                return EXIT_FAILURE;
        }

        if (trace_debuggee(&dbg) != 0) {
                (void)(fprintf(stderr, COLOR_RED
                        "Error while tracing debuggee.\n" COLOR_RESET));
                free_debugger(&dbg);
                return EXIT_FAILURE;
        }

        free_debugger(&dbg);
        return EXIT_SUCCESS;
}
