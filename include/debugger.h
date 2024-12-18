#pragma once

#include "debuggee.h"

typedef enum { DETACHED = 1, ATTACHED = 2 } debugger_state;

typedef struct debugger {
        debuggee dbgee;       /**< Debuggee that is debugged by this debugger */
        debugger_state state; /**< Current state of the debugger process */
} debugger;

void init_debugger(debugger *dbg, const char *debuggee_name);
void free_debugger(debugger *dbg);

int start_debuggee(debugger *dbg);
int trace_debuggee(debugger *dbg);
