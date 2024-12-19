#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "debuggee.h"
#include "debugger.h"
#include "debugger_commands.h"

command_t get_command_type(const char *command) {
        static const CommandMapping command_map[] = {
            {"help", CLI_HELP},      {"exit", CLI_EXIT},     {"run", DBG_RUN},
            {"regs", DBG_REGISTERS}, {"hbreak", DBG_HBREAK}, {"dump", DBG_DUMP},
            {"dis", DBG_DIS},        {"step", DBG_STEP},     {"over", DBG_OVER},
            {"out", DBG_OUT},
        };

        for (size_t i = 0; i < sizeof(command_map) / sizeof(command_map[0]);
             ++i) {
                if (strcmp(command, command_map[i].command) == 0) {
                        return command_map[i].type;
                }
        }

        return UNKNOWN;
}

int read_and_handle_user_command(debugger *dbg) {
        char *command = NULL;
        size_t len = 0;
        ssize_t read;

        while (true) {
                printf("Z: ");
                (void)(fflush(stdout));
                read = getline(&command, &len, stdin);
                if (read == -1) {
                        if (feof(stdin)) {
                                free(command);
                                free_debugger(dbg);
                                exit(0);
                        } else {
                                perror("getline");
                                printf("Failed to read command. Continuing "
                                       "execution.\n");
                        }

                        free(command);

                        if (ptrace(PTRACE_CONT, dbg->dbgee.pid, NULL, NULL) ==
                            -1) {
                                perror("ptrace CONT");
                                return EXIT_FAILURE;
                        }

                        dbg->dbgee.state = RUNNING;
                        return EXIT_SUCCESS;
                }

                // Remove trailing newline character
                command[strcspn(command, "\n")] = '\0';

                command_t cmd_type = get_command_type(command);

                if (handle_user_input(dbg, cmd_type, command) == EXIT_SUCCESS) {
                        break;
                }
        }

        free(command);
        return EXIT_SUCCESS;
}

// On EXIT_FAILURE we prompt the user again
int handle_user_input(debugger *dbg, command_t cmd_type, char *command) {
        switch (cmd_type) {
        case UNKNOWN:
                printf("Unknown command: %s\n", command);
                return EXIT_FAILURE;

        case CLI_EXIT:
                free_debugger(dbg);
                printf("Exiting debugger.\n");
                exit(0);
                return EXIT_FAILURE;

        case CLI_HELP:
                Help();
                return EXIT_FAILURE;

        case DBG_RUN:
                if (Run(&dbg->dbgee) != 0) {
                        printf("Run command failed.\n");
                        return EXIT_FAILURE;
                }
                return EXIT_SUCCESS;

        case DBG_REGISTERS:
                if (Registers(&dbg->dbgee) != 0) {
                        printf("Failed to retrieve registers.\n");
                }
                return EXIT_FAILURE;

        case DBG_HBREAK:
                if (Hbreak(&dbg->dbgee) != 0) {
                        printf("Failed to set hardware breakpoint.\n");
                }
                return EXIT_FAILURE;

        case DBG_DUMP:
                if (Dump(&dbg->dbgee) != 0) {
                        printf("Failed to dump memory.\n");
                }
                return EXIT_FAILURE;

        case DBG_DIS:
                if (Disassemble(&dbg->dbgee) != 0) {
                        printf("Failed to dump memory.\n");
                }
                return EXIT_FAILURE;

        case DBG_STEP:
                if (Step(&dbg->dbgee) != 0) {
                        printf("Failed to single step.\n");
                }
                return EXIT_FAILURE;

        case DBG_OVER:
                if (StepOver(&dbg->dbgee) != 0) {
                        printf("Failed to step over.\n");
                }
                return EXIT_FAILURE;

        case DBG_OUT:
                if (StepOut(&dbg->dbgee) != 0) {
                        printf("Failed to step out.\n");
                }
                return EXIT_FAILURE;

        default:
                printf("Unhandled command type for command: %s\n", command);
                return EXIT_FAILURE;
        }
}
