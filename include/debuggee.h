#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "breakpoint_handler.h"

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
        breakpoint_handler *bp_handler;
        bool has_run;
} debuggee;

void Help(void);

int Run(debuggee *dbgee);
int Continue(debuggee *dbgee);
int Registers(debuggee *dbgee);
int Dump(debuggee *dbgee);
int Disassemble(debuggee *dbgee);
int Step(debuggee *dbgee);
int StepOver(debuggee *dbgee);
int StepOut(debuggee *dbgee);

int SetSoftwareBreakpoint(debuggee *dbgee, const char *arg);
int SetHardwareBreakpoint(debuggee *dbgee, const char *arg);
int RemoveBreakpoint(debuggee *dbgee, const char *arg);
void ListBreakpoints(debuggee *dbgee);

int read_debug_register(pid_t pid, unsigned long offset, unsigned long *value);
int read_rip(debuggee *dbgee, unsigned long *rip);
int set_debug_register(pid_t pid, unsigned long offset, unsigned long value);
int configure_dr7(pid_t pid, int bpno, int condition, int length, bool enable);
int read_memory(pid_t pid, unsigned long address, unsigned char *buf,
                size_t size);
uint64_t set_sw_breakpoint(pid_t pid, uint64_t addr);
int replace_sw_breakpoint(pid_t pid, uint64_t addr, uint64_t old_byte);
bool is_software_breakpoint(debuggee *dbgee, size_t *bp_index_out);
int set_temp_sw_breakpoint(debuggee *dbgee, uint64_t addr);
int handle_software_breakpoint(debuggee *dbgee, size_t bp_index);
int remove_all_breakpoints(debuggee *dbgee);
bool breakpoint_exists(const debuggee *dbgee, unsigned long address);

bool is_call_instruction(debuggee *dbgee, unsigned long rip);
