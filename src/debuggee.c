#include "debuggee.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

int Run(debuggee *dbgee) {
        if (dbgee->state != STOPPED) {
                (void)(fprintf(
                    stderr,
                    "Debuggee is not in a stopped state. Current state: %d\n",
                    dbgee->state));
                return EXIT_FAILURE;
        }

        if (ptrace(PTRACE_CONT, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace CONT");
                return EXIT_FAILURE;
        }

        dbgee->state = RUNNING;
        return EXIT_SUCCESS;
}
