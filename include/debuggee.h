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

void Help(void);

int Run(debuggee *dbgee);
int Registers(debuggee *dbgee);
int Hbreak(debuggee *dbgee);

int read_debug_register(pid_t pid, unsigned long offset, unsigned long *value);
int set_debug_register(pid_t pid, unsigned long offset, unsigned long value);
int configure_dr7(pid_t pid, int bpno);
