#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debuggee.h"
#include "debugger.h"
#include "debugger_commands.h"

void init_debugger(debugger *dbg, const char *debuggee_name) {
        dbg->dbgee.pid = -1;
        dbg->dbgee.name = debuggee_name;
        dbg->dbgee.state = IDLE;
        dbg->state = DETACHED;
}

// Note: Because we are using PTRACE_O_EXITKILL the debuggee should also
// be killed when we detach
void free_debugger(debugger *dbg) {
        if (dbg->state == ATTACHED) {
                if (ptrace(PTRACE_DETACH, dbg->dbgee.pid, NULL, NULL) == -1) {
                        (void)(fprintf(
                            stderr,
                            "Failed to detach from child with PID %d: %s\n",
                            dbg->dbgee.pid, strerror(errno)));
                } else {
                        printf("Detached from child with PID: %d\n",
                               dbg->dbgee.pid);
                }
        }

        if ((dbg->dbgee.state == RUNNING) || (dbg->dbgee.state == STOPPED)) {
                if (kill(dbg->dbgee.pid, SIGKILL) == -1) {
                        (void)(fprintf(stderr,
                                       "Failed to kill child with PID %d: %s\n",
                                       dbg->dbgee.pid, strerror(errno)));
                } else {
                        printf("Killed child with PID: %d\n", dbg->dbgee.pid);
                }
        } else if (dbg->dbgee.state == TERMINATED) {
                printf("Child with PID %d has already terminated.\n",
                       dbg->dbgee.pid);
        }

        dbg->dbgee.pid = -1;
        dbg->dbgee.state = TERMINATED;
        dbg->state = DETACHED;
}

int start_debuggee(debugger *dbg) {
        pid_t pid = fork();
        if (pid == -1) {
                perror("fork");
                return -1;
        }

        if (pid == 0) { // Child process
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                        perror("ptrace");
                        exit(EXIT_FAILURE);
                }
                execl(dbg->dbgee.name, dbg->dbgee.name, NULL);
                perror("execl");
                exit(EXIT_FAILURE);
        } else { // Parent process
                dbg->dbgee.pid = pid;
                dbg->dbgee.state = RUNNING;
                printf("Child process started with PID %d\n", dbg->dbgee.pid);
        }

        return EXIT_SUCCESS;
}

int trace_debuggee(debugger *dbg) {
        bool ptrace_options_set = false;

        dbg->state = ATTACHED;
        while (dbg->state == ATTACHED) {
                int status;
                pid_t pid = waitpid(dbg->dbgee.pid, &status, 0);

                if (pid == -1) {
                        if (errno == EINTR) {
                                continue;
                        }
                        perror("waitpid");
                        return EXIT_FAILURE;
                }

                if (ptrace_options_set == false) {
                        if (ptrace(PTRACE_SETOPTIONS, dbg->dbgee.pid, 0,
                                   PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC) ==
                            -1) {
                                perror("ptrace SETOPTIONS");
                                dbg->dbgee.pid = -1;
                                dbg->dbgee.state = TERMINATED;
                                return EXIT_FAILURE;
                        }
                        ptrace_options_set = true;
                }

                if (WIFEXITED(status)) {
                        printf("Child %d exited with status %d.\n", pid,
                               WEXITSTATUS(status));
                        dbg->state = DETACHED;
                        dbg->dbgee.state = TERMINATED;
                        break;
                }

                if (WIFSIGNALED(status)) {
                        printf("Child %d was killed by signal %d.\n", pid,
                               WTERMSIG(status));
                        dbg->state = DETACHED;
                        dbg->dbgee.state = TERMINATED;
                        break;
                }

                if (WIFSTOPPED(status)) {
                        int sig = WSTOPSIG(status);
                        printf("Child %d stopped by signal %d.\n", pid, sig);
                        dbg->dbgee.state = STOPPED;

                        if (read_and_handle_user_command(dbg) != EXIT_SUCCESS) {
                                return EXIT_FAILURE;
                        }
                }
        }

        return EXIT_SUCCESS;
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

        default:
                printf("Unhandled command type for command: %s\n", command);
                return EXIT_FAILURE;
        }
}
