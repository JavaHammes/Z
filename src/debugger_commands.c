#include <string.h>

#include "debugger_commands.h"

command_type get_command_type(const char *command) {
        if (strcmp(command, "run") == 0) {
                return CMD_RUN;
        }
        if (strcmp(command, "continue") == 0 || strcmp(command, "cont") == 0) {
                return CMD_CONTINUE;
        }
        if (strcmp(command, "step") == 0) {
                return CMD_STEP;
        }
        if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0) {
                return CMD_TERMINATE;
        }
        return CMD_UNKNOWN;
}
