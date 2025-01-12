#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "breakpoint_handler.h"
#include "symtab.h"

typedef enum {
        IDLE = 0,
        RUNNING = 1,
        STOPPED = 2,
        TERMINATED = 3,
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
int RemoveBreakpoint(debuggee *dbgee, const char *arg);
void ListBreakpoints(debuggee *dbgee);

bool parse_breakpoint_argument(debuggee *dbgee, const char *arg,
                               uintptr_t *address_out);
bool is_valid_address(debuggee *dbgee, unsigned long addr);

int read_debug_register(pid_t pid, unsigned long offset, unsigned long *value);
bool get_available_debug_register(debuggee *dbgee, int *bpno,
                                  unsigned long *dr_offset);
int read_rip(debuggee *dbgee, unsigned long *rip);
int set_rip(debuggee *dbgee, unsigned long rip);
int read_memory(pid_t pid, unsigned long address, unsigned char *buf,
                size_t size);
int set_debug_register(pid_t pid, unsigned long offset, unsigned long value);
int configure_dr7(pid_t pid, int bpno, int condition, int length, bool enable);
int get_return_address(debuggee *dbgee, unsigned long *ret_addr_out);

bool set_sw_breakpoint(pid_t pid, uint64_t addr, uint64_t *code_at_addr);
int set_temp_sw_breakpoint(debuggee *dbgee, uint64_t addr);
int replace_sw_breakpoint(pid_t pid, uint64_t addr, uint64_t old_byte);
bool breakpoint_exists(const debuggee *dbgee, unsigned long address);
bool is_software_breakpoint(debuggee *dbgee, size_t *bp_index_out);
int handle_software_breakpoint(debuggee *dbgee, size_t bp_index);
int remove_all_breakpoints(debuggee *dbgee);

bool is_call_instruction(debuggee *dbgee, unsigned long rip);

unsigned long get_load_base(debuggee *dbgee);
unsigned long get_module_base_address(pid_t pid, unsigned long rip,
                                      char *module_name,
                                      size_t module_name_size);
unsigned long get_symbol_offset(debuggee *dbgee, const char *symbol_name);
unsigned long get_main_absolute_address(debuggee *dbgee);

bool step_and_wait(debuggee *dbgee);
