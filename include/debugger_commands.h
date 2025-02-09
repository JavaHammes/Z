#pragma once

#include "debugger.h"

typedef enum {
        CLI_HELP,
        CLI_EXIT,
        CLI_CLEAR,
        CLI_LOG,
        DBG_RUN,
        DBG_CONTINUE,
        DBG_STEP,
        DBG_STEP_OVER,
        DBG_STEP_OUT,
        DBG_SKIP,
        DBG_JUMP,
        DBG_TRACE,
        DBG_REGISTERS,
        DBG_SET_REG,
        DBG_BREAK,
        DBG_HBREAK,
        DBG_WATCH,
        DBG_CATCH,
        DBG_LIST_BREAKPOINTS,
        DBG_REMOVE_BREAKPOINT,
        DBG_DUMP,
        DBG_PATCH,
        DBG_DIS,
        DBG_GLOB_VARS,
        DBG_FUNC_NAMES,
        DBG_BACKTRACE,
        DBG_ADDR,
        UNKNOWN
} command_t;

typedef struct {
        const char *command;
        command_t type;
} command_mapping;

int read_and_handle_user_command(debugger *dbg);
int handle_user_input(debugger *dbg, command_t cmd_type, const char *arg);
