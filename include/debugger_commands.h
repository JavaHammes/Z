#pragma once

typedef enum {
        CMD_RUN,
        CMD_CONTINUE,
        CMD_STEP,
        CMD_TERMINATE,
        CMD_UNKNOWN
} command_t;

command_t get_command_type(const char *command);
