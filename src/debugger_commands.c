#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linenoise.h"

#include "debuggee.h"
#include "debugger.h"
#include "debugger_commands.h"
#include "ui.h"

static const command_mapping command_map[] = {
    {"help", CLI_HELP},
    {"exit", CLI_EXIT},
    {"clear", CLI_CLEAR},
    {"log", CLI_LOG},
    {"run", DBG_RUN},
    {"con", DBG_CONTINUE},
    {"step", DBG_STEP},
    {"over", DBG_STEP_OVER},
    {"out", DBG_STEP_OUT},
    {"skip", DBG_SKIP},
    {"jump", DBG_JUMP},
    {"trace", DBG_TRACE},
    {"regs", DBG_REGISTERS},
    {"set", DBG_SET_REG},
    {"break", DBG_BREAK},
    {"hbreak", DBG_HBREAK},
    {"watch", DBG_WATCH},
    {"catch", DBG_CATCH},
    {"points", DBG_LIST_BREAKPOINTS},
    {"remove", DBG_REMOVE_BREAKPOINT},
    {"dump", DBG_DUMP},
    {"patch", DBG_PATCH},
    {"dis", DBG_DIS},
    {"vars", DBG_GLOB_VARS},
    {"funcs", DBG_FUNC_NAMES},
    {"backt", DBG_BACKTRACE},
    {"addr", DBG_ADDR},
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
                printf(COLOR_RED);
                (void)(fflush(stdout));
                char *confirm =
                    linenoise("Are you sure you want to exit? (y/n): ");
                (void)(printf(COLOR_RESET));

                if (confirm != NULL) {
                        if (confirm[0] == 'y' || confirm[0] == 'Y') {
                                free_debugger(dbg);
                                printf(COLOR_RED
                                       "Exiting debugger.\n" COLOR_RESET);
                                free(confirm);
                                exit(EXIT_SUCCESS);
                        } else {
                                printf(COLOR_GREEN
                                       "Exit canceled.\n" COLOR_RESET);
                        }
                        free(confirm);
                } else {
                        printf(COLOR_YELLOW "\nExit canceled (no confirmation "
                                            "received).\n" COLOR_RESET);
                }
                return PROMPT_USER_AGAIN;
        }

        case CLI_HELP:
                Help();
                return PROMPT_USER_AGAIN;

        case CLI_CLEAR:
                linenoiseClearScreen();
                return PROMPT_USER_AGAIN;

        case CLI_LOG:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: log <filename>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (Log(arg) != 0) {
                        printf(COLOR_RED "Failed to log to '%s'.\n" COLOR_RESET,
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_RUN:
                if (Run(&dbg->dbgee) != 0) {
                        printf(COLOR_RED "Run command failed.\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                return DONT_PROMPT_USER_AGAIN;

        case DBG_CONTINUE:
                if (Continue(&dbg->dbgee) != 0) {
                        printf(COLOR_RED
                               "Continue command failed.\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                return DONT_PROMPT_USER_AGAIN;

        case DBG_STEP:
                if (Step(&dbg->dbgee) != 0) {
                        printf(COLOR_RED
                               "Failed to single step.\n" COLOR_RESET);
                }
                return PROMPT_USER_AGAIN;

        case DBG_STEP_OVER:
                if (StepOver(&dbg->dbgee) != 0) {
                        printf(COLOR_RED "Failed to step over.\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                return DONT_PROMPT_USER_AGAIN;

        case DBG_STEP_OUT:
                if (StepOut(&dbg->dbgee) != 0) {
                        printf(COLOR_RED "Failed to step out.\n" COLOR_RESET);
                }
                return DONT_PROMPT_USER_AGAIN;

        case DBG_SKIP:
                if (arg == NULL) {
                        printf(COLOR_YELLOW "Usage: skip <n>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (Skip(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED
                               "Failed to skip '%s' times.\n" COLOR_RESET,
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_JUMP:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: jump "
                               "<addr>|*<offset>|&<func_name>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (Jump(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED
                               "Failed to jump to '%s'.\n" COLOR_RESET,
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_TRACE:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: trace "
                               "<addr>|*<offset>|&<func_name>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (Trace(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED "Failed to trace '%s'.\n" COLOR_RESET,
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_REGISTERS:
                if (Registers(&dbg->dbgee) != 0) {
                        printf(COLOR_RED
                               "Failed to retrieve registers.\n" COLOR_RESET);
                }
                return PROMPT_USER_AGAIN;

        case DBG_SET_REG:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: set <reg>=<value>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }

                if (SetRegister(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED
                               "Failed to set register '%s'.\n" COLOR_RESET,
                               arg);
                }

                return PROMPT_USER_AGAIN;

        case DBG_BREAK:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: break "
                               "<addr>|*<offset>|&<func_name>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (SetSoftwareBreakpoint(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED "Failed to set software breakpoint at "
                                         "'%s'.\n" COLOR_RESET,
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_HBREAK:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: hbreak "
                               "<addr>|*<offset>|&<func_name>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (SetHardwareBreakpoint(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED "Failed to set hardware breakpoint at "
                                         "'%s'.\n" COLOR_RESET,
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_WATCH:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: watch "
                               "<addr>|*<offset>|&<glob_var>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (SetWatchpoint(&dbg->dbgee, arg) != 0) {
                        printf(
                            COLOR_RED
                            "Failed to set watchpoint at '%s'.\n" COLOR_RESET,
                            arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_CATCH:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: catch <sig_num>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (SetCatchpoint(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED "Failed to set catchpoint for signal "
                                         "'%s'.\n" COLOR_RESET,
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_LIST_BREAKPOINTS:
                ListBreakpoints(&dbg->dbgee);
                return PROMPT_USER_AGAIN;

        case DBG_REMOVE_BREAKPOINT:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: remove <idx>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (RemoveBreakpoint(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED "Failed to remove breakpoint at "
                                         "index: <%s>.\n" COLOR_RESET,
                               arg);
                };
                return PROMPT_USER_AGAIN;

        case DBG_DUMP:
                if (Dump(&dbg->dbgee) != 0) {
                        printf(COLOR_RED
                               "Failed to dump memory.\n" COLOR_RESET);
                }
                return PROMPT_USER_AGAIN;

        case DBG_PATCH:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: patch "
                               "<addr>|*<offset>=<opcode(s)> (No spaces "
                               "between opcodes)\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (Patch(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED "Failed to patch "
                                         "'%s'.\n" COLOR_RESET,
                               arg);
                }
                return PROMPT_USER_AGAIN;

        case DBG_DIS:;
                if (Disassemble(&dbg->dbgee) != 0) {
                        printf(COLOR_RED
                               "Failed to disassemble memory.\n" COLOR_RESET);
                }
                return PROMPT_USER_AGAIN;

        case DBG_GLOB_VARS:
                if (DisplayGlobalVariables(&dbg->dbgee) != 0) {
                        printf(COLOR_RED "Failed to display global "
                                         "variables.\n" COLOR_RESET);
                }
                return PROMPT_USER_AGAIN;

        case DBG_FUNC_NAMES:
                if (DisplayFunctionNames(&dbg->dbgee) != 0) {
                        printf(
                            COLOR_RED
                            "Failed to display function names.\n" COLOR_RESET);
                }
                return PROMPT_USER_AGAIN;

        case DBG_BACKTRACE:
                if (Backtrace(&dbg->dbgee) != 0) {
                        printf(COLOR_RED
                               "Failed to display backtrace.\n" COLOR_RESET);
                }
                return PROMPT_USER_AGAIN;

        case DBG_ADDR:
                if (arg == NULL) {
                        printf(COLOR_YELLOW
                               "Usage: addr <func_name>\n" COLOR_RESET);
                        return PROMPT_USER_AGAIN;
                }
                if (Address(&dbg->dbgee, arg) != 0) {
                        printf(COLOR_RED "Failed to get address for func: "
                                         "<%s>.\n" COLOR_RESET,
                               arg);
                };
                return PROMPT_USER_AGAIN;

        case UNKNOWN:
                printf(COLOR_YELLOW "Unknown command.\n" COLOR_RESET);
                return PROMPT_USER_AGAIN;

        default:
                printf(COLOR_RED "Unhandled command type.\n" COLOR_RESET);
                return PROMPT_USER_AGAIN;
        }
}

int read_and_handle_user_command(debugger *dbg) {
        char *input = NULL;
        char *last_command = NULL;

        linenoiseHistorySetMaxLen(LINENOISE_MAX_HISTORY_LENGTH);
        linenoiseSetCompletionCallback(_completion);

        while (true) {
                printf(COLOR_RESET);
                (void)(fflush(stdout));

                input = linenoise("<- Z -> ");
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
                                printf(
                                    COLOR_GREEN
                                    "Repeating last command: %s\n" COLOR_RESET,
                                    last_command);
                                free(input);
                                input = strdup(last_command);
                        } else {
                                printf(COLOR_YELLOW "No previous command to "
                                                    "repeat.\n" COLOR_RESET);
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
