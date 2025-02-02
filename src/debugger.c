#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/limits.h>
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

int set_ld_preload(const char *libs[], size_t count) {
        if (count == 0) {
                (void)(fprintf(stderr,
                               "No libraries provided to set_ld_preload.\n"));
                return -1;
        }

        char exe_path[PATH_MAX];
        ssize_t len =
            readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);

        if (len == -1) {
                perror("readlink");
                return -1;
        }

        exe_path[len] = '\0';

        char *dir = dirname(exe_path);
        if (dir == NULL) {
                perror("dirname");
                return -1;
        }

        char ld_preload_value[PATH_MAX * count];
        ld_preload_value[0] = '\0';

        for (size_t i = 0; i < count; ++i) {
                char preload_path[PATH_MAX];
                if ((unsigned long)(snprintf(preload_path, sizeof(preload_path),
                                             "%s/%s", dir, libs[i])) >=
                    sizeof(preload_path)) {
                        (void)(fprintf(stderr, "Path too long for %s\n",
                                       libs[i]));
                        return -1;
                }

                if (access(preload_path, R_OK) == -1) {
                        (void)(fprintf(stderr,
                                       "Shared library not found at: %s\n",
                                       preload_path));
                        return -1;
                }

                if (i > 0) {
                        strncat(ld_preload_value, ":",
                                sizeof(ld_preload_value) -
                                    strlen(ld_preload_value) - 1);
                }
                strncat(ld_preload_value, preload_path,
                        sizeof(ld_preload_value) - strlen(ld_preload_value) -
                            1);
        }

        if (setenv("LD_PRELOAD", ld_preload_value, 1) == -1) {
                perror("setenv");
                return -1;
        }

        return 0;
}

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
                const char *libs[] = {"libptrace_intercept.so",
                                      "libfopen_intercept.so",
                                      "libprctl_intercept.so"};
                size_t lib_count = sizeof(libs) / sizeof(libs[0]);

                if (set_ld_preload(libs, lib_count) != 0) {
                        (void)(fprintf(stderr, "Failed to set LD_PRELOAD.\n"));
                        exit(EXIT_FAILURE);
                }

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

int trace_debuggee(debugger *dbg) { // NOLINT
        bool ptrace_options_set = false;
        bool main_startup_breakpoint_set = false;

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
                                   PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC |
                                       PTRACE_O_TRACEFORK |
                                       PTRACE_O_TRACEVFORK |
                                       PTRACE_O_TRACECLONE |
                                       PTRACE_O_TRACEEXIT) == -1) {
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

                        unsigned long event =
                            (status >> PTRACE_EVENT_SHIFT) & PTRACE_EVENT_MASK;
                        dbg->dbgee.state = STOPPED;

                        if (main_startup_breakpoint_set == false) {
                                unsigned long main_address =
                                    get_main_absolute_address(&dbg->dbgee);

                                if (main_address == 0) {
                                        (void)(fprintf(stderr,
                                                       "Failed to retrieve "
                                                       "'main' address.\n"));
                                        return EXIT_FAILURE;
                                }

                                set_temp_sw_breakpoint(&dbg->dbgee,
                                                       main_address);

                                if (ptrace(PTRACE_CONT, dbg->dbgee.pid, NULL,
                                           NULL) == -1) {
                                        perror("ptrace CONT after setting "
                                               "breakpoint");
                                        return EXIT_FAILURE;
                                }

                                main_startup_breakpoint_set = true;
                                continue;
                        }

                        size_t sw_bp_index;
                        size_t hw_bp_index;
                        size_t cp_signal_index;
                        bool breakpoint_handled = false;

                        if (is_software_breakpoint(&dbg->dbgee, &sw_bp_index)) {
                                breakpoint_handled = true;
                                if (handle_software_breakpoint(&dbg->dbgee,
                                                               sw_bp_index) !=
                                    EXIT_SUCCESS) {
                                        return EXIT_FAILURE;
                                }
                        }

                        if (is_hardware_breakpoint(&dbg->dbgee, &hw_bp_index)) {
                                breakpoint_handled = true;
                                if (handle_hardware_breakpoint(&dbg->dbgee,
                                                               hw_bp_index) !=
                                    EXIT_SUCCESS) {
                                        return EXIT_FAILURE;
                                }
                        }

                        if (is_catchpoint_signal(&dbg->dbgee, &cp_signal_index,
                                                 sig)) {
                                breakpoint_handled = true;
                                if (handle_catchpoint_signal(&dbg->dbgee,
                                                             cp_signal_index) !=
                                    EXIT_SUCCESS) {
                                        return EXIT_FAILURE;
                                }
                        }

                        if (event != 0) {
                                size_t cp_event_index;
                                if (is_catchpoint_event(
                                        &dbg->dbgee, &cp_event_index, event)) {
                                        breakpoint_handled = true;
                                        if (handle_catchpoint_event(
                                                &dbg->dbgee, cp_event_index) !=
                                            EXIT_SUCCESS) {
                                                return EXIT_FAILURE;
                                        }
                                } else {
                                        printf("Ignoring event %lx.\n\r",
                                               event);
                                        if (ptrace(PTRACE_CONT, dbg->dbgee.pid,
                                                   NULL, NULL) == -1) {
                                                perror("ptrace CONT to ignore "
                                                       "event");
                                                return EXIT_FAILURE;
                                        }
                                        continue;
                                }
                        }

                        if (!breakpoint_handled &&
                            dbg->dbgee.state != SINGLE_STEPPING) {

                                // If we receive a SIGTRAP that is neither from
                                // a breakpoint nor a single-step event, it must
                                // have originated from the debuggee rather than
                                // our debugger. To counter anti-debugging
                                // techniques, we need to forward it back to the
                                // debuggee.
                                if (sig == SIGTRAP) {
                                        printf("[INFO] Sending SIGTRAP back to "
                                               "debuggee.\n\r");

                                        if (ptrace(PTRACE_CONT, dbg->dbgee.pid,
                                                   NULL, SIGTRAP) == -1) {
                                                perror("ptrace CONT to send "
                                                       "SIGTRAP");
                                                return EXIT_FAILURE;
                                        }
                                        continue;
                                }

                                printf("Ignoring signal %d.\n\r", sig);
                                if (ptrace(PTRACE_CONT, dbg->dbgee.pid, NULL,
                                           NULL) == -1) {
                                        perror("ptrace CONT to ignore signal");
                                        return EXIT_FAILURE;
                                }
                                continue;
                        }

                        if (read_and_handle_user_command(dbg) != EXIT_SUCCESS) {
                                return EXIT_FAILURE;
                        }
                }
        }

        return EXIT_SUCCESS;
}
