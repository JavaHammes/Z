#pragma once

#include "debugger.h"

typedef enum {
        CLI_EXIT,
        CLI_HELP,
        DBG_RUN,
        DBG_REGISTERS,
        DBG_HBREAK,
        DBG_DUMP,
        DBG_DIS,
        UNKNOWN
} command_t;

command_t get_command_type(const char *command);

int read_and_handle_user_command(debugger *dbg);
int handle_user_input(debugger *dbg, command_t cmd_type, char *command);
