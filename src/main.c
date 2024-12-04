#include "debugger.h"
#include "macros.h"

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

bool file_exists(const char *filename);

int main(int argc, char **argv) {
        if (argc < 2) {
                FATAL("Usage: %s <debug_target>\n", argv[0]);
        }

        const char *debuggee_name = argv[1];

        if (!file_exists(debuggee_name)) {
                FATAL("Cannot find executable %s", debuggee_name);
        }

        debugger dbg;
        init_dbg(&dbg, debuggee_name);

        if (start_dbg(&dbg) != 0) {
                free_dbg(&dbg);
                return EXIT_FAILURE;
        }

        free_dbg(&dbg);

        return EXIT_SUCCESS;
}

bool file_exists(const char *filename) { return access(filename, F_OK) == 0; }
