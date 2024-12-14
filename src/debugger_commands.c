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
        if (strcmp(command, "continue") == 0 || strcmp(command, "cont") == 0) {
                return DBG_CONTINUE;
        }
        if (strcmp(command, "step") == 0) {
                return DBG_STEP;
        }
        if (strcmp(command, "quit") == 0) {
                return DBG_TERMINATE;
        }

        return UNKNOWN;
}
