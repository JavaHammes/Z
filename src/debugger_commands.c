#include "linenoise.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debuggee.h"
#include "debugger.h"
#include "debugger_commands.h"

static const command_mapping command_map[] = {
    {"help", CLI_HELP},
    {"exit", CLI_EXIT},
    {"clear", CLI_CLEAR},
    {"run", DBG_RUN},
    {"con", DBG_CONTINUE},
    {"step", DBG_STEP},
    {"over", DBG_STEP_OVER},
    {"out", DBG_STEP_OUT},
    {"skip", DBG_SKIP},
    {"jump", DBG_JUMP},
    {"trace", DBG_TRACE},
    {"regs", DBG_REGISTERS},
    {"break", DBG_BREAK},
    {"hbreak", DBG_HBREAK},
    {"watch", DBG_WATCH},
    {"catch", DBG_CATCH},
    {"points", DBG_LIST_BREAKPOINTS},
    {"remove", DBG_REMOVE_BREAKPOINT},
    {"dump", DBG_DUMP},
    {"dis", DBG_DIS},
    {"vars", DBG_GLOB_VARS},
    {"funcs", DBG_FUNC_NAMES},
};

enum {
        PROMPT_USER_AGAIN = 1,
        DONT_PROMPT_USER_AGAIN = 0,
        LINENOISE_MAX_HISTORY_LENGTH = 100,
};

static command_t _get_command_type(const char *command) {
        size_t map_size = sizeof(command_map) / sizeof(command_map[0]);

        for (size_t i = 0; i < map_size; ++i) {
                if (strcmp(command, command_map[i].command) == 0) {
                        return command_map[i].type;
                }
        }

        return UNKNOWN;
}

static void _completion(const char *buf, linenoiseCompletions *lc) {
        size_t buf_len = strlen(buf);
        size_t map_size = sizeof(command_map) / sizeof(command_map[0]);

        for (size_t i = 0; i < map_size; ++i) {
                if (strncmp(buf, command_map[i].command, buf_len) == 0) {
                        linenoiseAddCompletion(lc, command_map[i].command);
                }
        }
}

int handle_user_input(debugger *dbg, command_t cmd_type, // NOLINT
                      const char *arg) {
        switch (cmd_type) {
        case CLI_EXIT: {
                char *confirm =
                    linenoise("Are you sure you want to exit? (y/n): ");
                if (confirm != NULL) {
                        if (confirm[0] == 'y' || confirm[0] == 'Y') {
                                free_debugger(dbg);
                                printf("Exiting debugger.\n");
                                free(confirm);
                                exit(EXIT_SUCCESS);
                        } else {
                                printf("Exit canceled.\n");
                        }
                        free(confirm);
                } else {
                        printf("\nExit canceled (no confirmation received).\n");
                }
                return PROMPT_USER_AGAIN;
        }

        case CLI_HELP:
                Help();
                return PROMPT_USER_AGAIN;

        case CLI_CLEAR:
                linenoiseClearScreen();
                return PROMPT_USER_AGAIN;

        case DBG_RUN:
                if (Run(&dbg->dbgee) != 0) {
                        printf("Run command failed.\n");
                        return PROMPT_USER_AGAIN;
                }
                return DONT_PROMPT_USER_AGAIN;

        case DBG_CONTINUE:
                if (Continue(&dbg->dbgee) != 0) {
                        printf("Continue command failed.\n");
                        return PROMPT_USER_AGAIN;
                }
                return DONT_PROMPT_USER_AGAIN;

        case DBG_STEP:
                if (Step(&dbg->dbgee) != 0) {
                        printf("Failed to single step.\n");
                }
                return PROMPT_USER_AGAIN;

        case DBG_STEP_OVER:
                if (StepOver(&dbg->dbgee) != 0) {
                        printf("Failed to step over.\n");
                        return PROMPT_USER_AGAIN;
                }
                return DONT_PROMPT_USER_AGAIN;

        case DBG_STEP_OUT:
                if (StepOut(&dbg->dbgee) != 0) {
                        printf("Failed to step out.\n");
                }
                return DONT_PROMPT_USER_AGAIN;

        case DBG_SKIP:
                if (arg == NULL) {
                        printf("Usage: skip <n>\n");
                        return PROMPT_USER_AGAIN;
                }
                if (Skip(&dbg->dbgee, arg) != 0) {
                        printf("Failed to skip '%s' times.\n", arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_JUMP:
                if (arg == NULL) {
                        printf("Usage: jump "
                               "<addr>|*<offset>|&<func_name>\n");
                        return PROMPT_USER_AGAIN;
                }
                if (Jump(&dbg->dbgee, arg) != 0) {
                        printf("Failed to jump to '%s'.\n", arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_TRACE:
                if (arg == NULL) {
                        printf("Usage: trace "
                               "<addr>|*<offset>|&<func_name>\n");
                        return PROMPT_USER_AGAIN;
                }
                if (Trace(&dbg->dbgee, arg) != 0) {
                        printf("Failed to trace '%s'.\n", arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_REGISTERS:
                if (Registers(&dbg->dbgee) != 0) {
                        printf("Failed to retrieve registers.\n");
                }
                return PROMPT_USER_AGAIN;

        case DBG_BREAK:
                if (arg == NULL) {
                        printf("Usage: break "
                               "<addr>|*<offset>|&<func_name>\n");
                        return PROMPT_USER_AGAIN;
                }
                if (SetSoftwareBreakpoint(&dbg->dbgee, arg) != 0) {
                        printf("Failed to set software breakpoint at '%s'.\n",
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_HBREAK:
                if (arg == NULL) {
                        printf("Usage: hbreak "
                               "<addr>|*<offset>|&<func_name>\n");
                        return PROMPT_USER_AGAIN;
                }
                if (SetHardwareBreakpoint(&dbg->dbgee, arg) != 0) {
                        printf("Failed to set hardware breakpoint at '%s'.\n",
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_WATCH:
                if (arg == NULL) {
                        printf("Usage: watch <addr>|*<offset>|&<glob_var>\n");
                        return PROMPT_USER_AGAIN;
                }
                if (SetWatchpoint(&dbg->dbgee, arg) != 0) {
                        printf("Failed to set watchpoint at '%s'.\n", arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_CATCH:
                if (arg == NULL) {
                        printf("Usage: catch <sig_num>\n");
                        return PROMPT_USER_AGAIN;
                }
                if (SetCatchpoint(&dbg->dbgee, arg) != 0) {
                        printf("Failed to set catchpoint for signal '%s'.\n",
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_LIST_BREAKPOINTS:
                ListBreakpoints(&dbg->dbgee);
                return PROMPT_USER_AGAIN;

        case DBG_REMOVE_BREAKPOINT:
                if (arg == NULL) {
                        printf("Usage: remove <idx>\n");
                        return PROMPT_USER_AGAIN;
                }
                if (RemoveBreakpoint(&dbg->dbgee, arg) != 0) {
                        printf("Failed to remove breakpoint at index: <%s>.\n",
                               arg);
                };
                return PROMPT_USER_AGAIN;

        case DBG_DUMP:
                if (Dump(&dbg->dbgee) != 0) {
                        printf("Failed to dump memory.\n");
                }
                return PROMPT_USER_AGAIN;

        case DBG_DIS:;
                if (Disassemble(&dbg->dbgee) != 0) {
                        printf("Failed to disassemble memory.\n");
                }
                return PROMPT_USER_AGAIN;

        case DBG_GLOB_VARS:
                if (DisplayGlobalVariables(&dbg->dbgee) != 0) {
                        printf("Failed to display global variables.\n");
                }
                return PROMPT_USER_AGAIN;

        case DBG_FUNC_NAMES:
                if (DisplayFunctionNames(&dbg->dbgee) != 0) {
                        printf("Failed to display function names.\n");
                }
                return PROMPT_USER_AGAIN;

        case UNKNOWN:
                printf("Unknown command.\n");
                return PROMPT_USER_AGAIN;

        default:
                printf("Unhandled command type.\n");
                return PROMPT_USER_AGAIN;
        }
}

int read_and_handle_user_command(debugger *dbg) {
        char *input = NULL;
        char *last_command = NULL;

        linenoiseHistorySetMaxLen(LINENOISE_MAX_HISTORY_LENGTH);
        linenoiseSetCompletionCallback(_completion);

        while (true) {
                input = linenoise("Z: ");
                if (input == NULL) {
                        if (errno == EAGAIN) {
                                handle_user_input(dbg, CLI_EXIT, "");
                                continue;
                        }
                        free_debugger(dbg);
                        exit(EXIT_FAILURE);
                }

                if (strcmp(input, "!!") == 0) {
                        if (last_command) {
                                printf("Repeating last command: %s\n",
                                       last_command);
                                free(input);
                                input = strdup(last_command);
                        } else {
                                printf("No previous command to repeat.\n");
                                free(input);
                                continue;
                        }
                } else {
                        linenoiseHistoryAdd(input);
                        free((void *)last_command);
                        last_command = strdup(input);
                }

                input[strcspn(input, "\n")] = '\0';

                char *command = strtok(input, " ");
                char *arg = strtok(NULL, " ");

                command_t cmd_type = UNKNOWN;
                if (command != NULL) {
                        cmd_type = _get_command_type(command);
                }

                if (handle_user_input(dbg, cmd_type, arg) == EXIT_SUCCESS) {
                        free(input);
                        break;
                }

                free(input);
        }

        free((void *)last_command);
        return EXIT_SUCCESS;
}
