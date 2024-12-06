#pragma once

typedef enum {
        CMD_RUN,
        CMD_CONTINUE,
        CMD_STEP,
        CMD_TERMINATE,
        CMD_UNKNOWN
} command_type;

command_type get_command_type(const char *command);
