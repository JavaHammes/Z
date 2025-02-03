#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "breakpoint_handler.h"
#include "symtab.h"

enum {
        PTRACE_EVENT_SHIFT = 16,
        PTRACE_EVENT_MASK = 0xFFFF,
};

typedef enum {
        IDLE = 0,
        RUNNING = 1,
        STOPPED = 2,
        SINGLE_STEPPING = 3,
        TERMINATED = 4,
} debuggee_state;

typedef struct debuggee {
        pid_t pid;
        const char *name;
        debuggee_state state;
        breakpoint_handler *bp_handler;
        bool has_run;
} debuggee;

void Help(void);

int Run(debuggee *dbgee);
int Continue(debuggee *dbgee);
int Step(debuggee *dbgee);
int StepOver(debuggee *dbgee);
int StepOut(debuggee *dbgee);
int Skip(debuggee *dbgee, const char *arg);
int Jump(debuggee *dbgee, const char *arg);
int Trace(debuggee *dbgee, const char *arg);
int Registers(debuggee *dbgee);
int Dump(debuggee *dbgee);
int Disassemble(debuggee *dbgee);
int DisplayGlobalVariables(debuggee *dbgee);
int DisplayFunctionNames(debuggee *dbgee);

int SetSoftwareBreakpoint(debuggee *dbgee, const char *arg);
int SetHardwareBreakpoint(debuggee *dbgee, const char *arg);
int SetWatchpoint(debuggee *dbgee, const char *arg);
int SetCatchpoint(debuggee *dbgee, const char *arg);
int RemoveBreakpoint(debuggee *dbgee, const char *arg);
void ListBreakpoints(debuggee *dbgee);

unsigned long get_entry_absolute_address(debuggee *dbgee);
int set_temp_sw_breakpoint(debuggee *dbgee, uint64_t addr);
bool is_software_breakpoint(debuggee *dbgee, size_t *bp_index_out);
bool is_hardware_breakpoint(debuggee *dbgee, size_t *bp_index_out);
bool is_catchpoint_signal(debuggee *dbgee, size_t *bp_index_out,
                          int signal_number);
bool is_catchpoint_event(debuggee *dbgee, size_t *bp_index_out,
                         unsigned long event_code);
int handle_software_breakpoint(debuggee *dbgee, size_t bp_index);
int handle_hardware_breakpoint(debuggee *dbgee, size_t bp_index);
int handle_catchpoint_signal(debuggee *dbgee, size_t bp_index);
int handle_catchpoint_event(debuggee *dbgee, size_t bp_index);
