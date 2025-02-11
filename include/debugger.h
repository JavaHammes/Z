#pragma once

#include "debuggee.h"
#include "ld_preload.h"

typedef enum { DETACHED = 1, ATTACHED = 2 } debugger_state;

typedef struct debugger {
        debuggee dbgee;
        debugger_state state;
        ld_preload_list *preload_list;
} debugger;

void init_debugger(debugger *dbg, const char *debuggee_name, int argc,
                   char **argv);
void free_debugger(debugger *dbg);

int start_debuggee(debugger *dbg);
int trace_debuggee(debugger *dbg);
