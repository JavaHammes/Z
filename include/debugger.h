#pragma once

#include "debuggee.h"

typedef enum { DETACHED = 1, ATTACHED = 2 } debugger_state;

typedef struct debugger {
        debuggee dbgee;       /**< Debuggee that is debugged by this debugger */
        debugger_state state; /**< Current state of the debugger process */
} debugger;

void init_dbg(debugger *dbg, const char *debuggee_name);
int start_dbg(debugger *dbg);
void free_dbg(debugger *dbg);

int start_debuggee(debugger *dbg);
int trace_debuggee(debugger *dbg);
