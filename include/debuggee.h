#pragma once

#include <sys/types.h>

typedef enum {
        IDLE = 0,
        RUNNING = 1,
        STOPPED = 2,
        TERMINATED = 3,
} debuggee_state;

typedef struct debuggee {
        pid_t pid;            /**< Process ID of the debuggee */
        const char *name;     /**< Name or path of the debuggee executable */
        debuggee_state state; /**< Current state of the debuggee process */
} debuggee;

int Run(debuggee *dbgee);
int Terminate(debuggee *dbgee);
int Break(debuggee *dbgee);
int Continue(debuggee *dbgee);
