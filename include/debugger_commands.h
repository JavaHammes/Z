#pragma once

typedef enum {
        CLI_EXIT,
        CLI_HELP,
        DBG_RUN,
        DBG_CONTINUE,
        DBG_STEP,
        DBG_TERMINATE,
        UNKNOWN
} command_t;

command_t get_command_type(const char *command);
