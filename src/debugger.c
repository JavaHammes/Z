#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debuggee.h"
#include "debugger.h"

void init_dbg(debugger *dbg, const char *debuggee_name) {
        dbg->dbgee.pid = -1;
        dbg->dbgee.name = debuggee_name;
        dbg->dbgee.state = IDLE;
        dbg->state = DETACHED;
}

int start_dbg(debugger *dbg) {
        if (start_debuggee(dbg) != 0) {
                (void)(fprintf(stderr, "Failed to start debuggee: %s",
                               dbg->dbgee.name));
                return EXIT_FAILURE;
        }

        if (trace_debuggee(dbg) != 0) {
                (void)(fprintf(stderr, "Failed to trace debuggee: %s",
                               dbg->dbgee.name));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

void free_dbg(debugger *dbg) {
        // Note: Because we are using PTRACE_O_EXITKILL the debuggee should also
        // be killed when we detach
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
                        printf("Killed child with PID: %d\nExiting...\n",
                               dbg->dbgee.pid);
                }
        } else if (dbg->dbgee.state == TERMINATED) {
                printf("Child with PID %d has already terminated.\n",
                       dbg->dbgee.pid);
        }

        dbg->dbgee.pid = -1;
        dbg->dbgee.state = TERMINATED;
        dbg->state = DETACHED;
}

/*
 * Sets dbge->dbgee.pid
 *      -> Success: Child pid
 *      -> Failure: -1
 * Sets dbg->dbgee.state
 *      -> Success: RUNNING
 *      -> Failure: TERMINATED
 */
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

                int status;
                if (waitpid(dbg->dbgee.pid, &status, 0) == -1) {
                        perror("waitpid");
                        dbg->dbgee.pid = -1;
                        dbg->dbgee.state = TERMINATED;
                        return EXIT_FAILURE;
                }

                if (WIFEXITED(status)) {
                        (void)(fprintf(
                            stderr,
                            "Child process exited prematurely with status %d\n",
                            WEXITSTATUS(status)));
                        dbg->dbgee.pid = -1;
                        dbg->dbgee.state = TERMINATED;
                        return EXIT_FAILURE;
                }

                if (ptrace(PTRACE_SETOPTIONS, dbg->dbgee.pid, 0,
                           PTRACE_O_EXITKILL) == -1) {
                        perror("ptrace SETOPTIONS");
                        dbg->dbgee.pid = -1;
                        dbg->dbgee.state = TERMINATED;
                        return EXIT_FAILURE;
                }

                // In the future we might not want to continue here
                if (ptrace(PTRACE_CONT, dbg->dbgee.pid, NULL, NULL) == -1) {
                        perror("ptrace CONT after SETOPTIONS");
                        dbg->dbgee.pid = -1;
                        dbg->dbgee.state = TERMINATED;
                        return EXIT_FAILURE;
                }

                printf("Child process started with PID %d\n", dbg->dbgee.pid);
        }

        return EXIT_SUCCESS;
}

int trace_debuggee(debugger *dbg) {
        dbg->state = ATTACHED;

        while (dbg->state == ATTACHED) {
                int status;
                pid_t pid = waitpid(dbg->dbgee.pid, &status, 0);
                if (pid == -1) {
                        if (errno == EINTR) {
                                continue; // Interrupted by signal, retry
                        }
                        perror("waitpid");
                        return EXIT_FAILURE;
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

                        // TODO: Handle specific signals if needed
                        // For example, handle breakpoints or single-stepping

                        // Continue the child process
                        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
                                perror("ptrace CONT");
                                return -1;
                        }

                        printf("Continued child process %d.\n", pid);
                        dbg->dbgee.state = RUNNING;
                }

                // TODO: Implement a mechanism to break the loop, such as
                // listening for user input to stop debugging
        }

        return EXIT_SUCCESS;
}
