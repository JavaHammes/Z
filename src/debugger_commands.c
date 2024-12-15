#include <string.h>

#include "debugger_commands.h"

command_t get_command_type(const char *command) {
        if (strcmp(command, "help") == 0) {
                return CLI_HELP;
        }
        if (strcmp(command, "exit") == 0) {
                return CLI_EXIT;
        }
        if (strcmp(command, "run") == 0) {
                return DBG_RUN;
        }
        if (strcmp(command, "registers") == 0) {
                return DBG_REGISTERS;
        }
        if (strcmp(command, "hbreak") == 0) {
                return DBG_HBREAK;
        }

        return UNKNOWN;
}
