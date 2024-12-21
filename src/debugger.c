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
        // Could be NULL. TODO: Catch this.
        dbg->dbgee.bp_handler = init_breakpoint_handler();
        dbg->state = DETACHED;
}

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
        free_breakpoint_handler(dbg->dbgee.bp_handler);
        dbg->state = DETACHED;
}

int start_debuggee(debugger *dbg) {
        pid_t pid = fork();
        if (pid == -1) {
                perror("fork");
                return -1;
        }

        if (pid == 0) {
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                        perror("ptrace");
                        exit(EXIT_FAILURE);
                }
                execl(dbg->dbgee.name, dbg->dbgee.name, NULL);
                perror("execl");
                exit(EXIT_FAILURE);
        } else {
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

                        size_t bp_index;
                        bool sw_bp_hit =
                            is_software_breakpoint(&dbg->dbgee, &bp_index);

                        if (sw_bp_hit) {
                                if (handle_software_breakpoint(&dbg->dbgee,
                                                               bp_index) !=
                                    EXIT_SUCCESS) {
                                        return EXIT_FAILURE;
                                }
                        }

                        if (read_and_handle_user_command(dbg) != EXIT_SUCCESS) {
                                return EXIT_FAILURE;
                        }
                }
        }

        return EXIT_SUCCESS;
}
