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

#include "colors.h"
#include "debuggee.h"
#include "debugger.h"
#include "debugger_commands.h"

int set_ld_preload(const char *libs[], size_t count) {
        if (count == 0) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "No libraries provided to set_ld_preload.\n" COLOR_RESET));
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
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Path too long for %s\n" COLOR_RESET,
                                       libs[i]));
                        return -1;
                }

                if (access(preload_path, R_OK) == -1) {
                        (void)(fprintf(
                            stderr,
                            COLOR_RED
                            "Shared library not found at: %s\n" COLOR_RESET,
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
        dbg->dbgee.has_run = false;

        // Could be NULL. TODO: Catch this.
        dbg->dbgee.bp_handler = init_breakpoint_handler();

        dbg->state = DETACHED;
}

void free_debugger(debugger *dbg) {
        if (dbg->state == ATTACHED) {
                if (ptrace(PTRACE_DETACH, dbg->dbgee.pid, NULL, NULL) == -1) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Failed to detach from child with PID "
                                       "%d: %s\n" COLOR_RESET,
                                       dbg->dbgee.pid, strerror(errno)));
                } else {
                        printf(COLOR_GREEN
                               "Detached from child with PID: %d\n" COLOR_RESET,
                               dbg->dbgee.pid);
                }
        }

        if (dbg->dbgee.state == RUNNING || dbg->dbgee.state == STOPPED ||
            dbg->dbgee.state == SINGLE_STEPPING) {
                if (kill(dbg->dbgee.pid, SIGKILL) == -1) {
                        (void)(fprintf(stderr,
                                       COLOR_RED "Failed to kill child with "
                                                 "PID %d: %s\n" COLOR_RESET,
                                       dbg->dbgee.pid, strerror(errno)));
                } else {
                        printf(COLOR_GREEN
                               "Killed child with PID: %d\n" COLOR_RESET,
                               dbg->dbgee.pid);
                }
        } else if (dbg->dbgee.state == TERMINATED) {
                printf(
                    COLOR_YELLOW
                    "Child with PID %d has already terminated.\n" COLOR_RESET,
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
                const char *libs[] = {
                    "libptrace_intercept.so", "libfopen_intercept.so",
                    "libgetenv_intercept.so", "libprctl_intercept.so"};
                size_t lib_count = sizeof(libs) / sizeof(libs[0]);

                if (set_ld_preload(libs, lib_count) != 0) {
                        (void)(fprintf(
                            stderr, COLOR_RED
                            "Failed to set LD_PRELOAD.\n" COLOR_RESET));
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
                printf(COLOR_GREEN
                       "Child process started with PID %d\n" COLOR_RESET,
                       dbg->dbgee.pid);
        }

        return EXIT_SUCCESS;
}

int trace_debuggee(debugger *dbg) { // NOLINT
        bool ptrace_options_set = false;
        bool entry_startup_breakpoint_set = false;

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
                        printf(COLOR_YELLOW
                               "Child %d exited with status %d.\n" COLOR_RESET,
                               pid, WEXITSTATUS(status));
                        dbg->state = DETACHED;
                        dbg->dbgee.state = TERMINATED;
                        break;
                }

                if (WIFSIGNALED(status)) {
                        printf(
                            COLOR_YELLOW
                            "Child %d was killed by signal %d.\n" COLOR_RESET,
                            pid, WTERMSIG(status));
                        dbg->state = DETACHED;
                        dbg->dbgee.state = TERMINATED;
                        break;
                }

                if (WIFSTOPPED(status)) {
                        int sig = WSTOPSIG(status);
                        unsigned long event =
                            (status >> PTRACE_EVENT_SHIFT) & PTRACE_EVENT_MASK;
                        dbg->dbgee.state = STOPPED;

                        if (entry_startup_breakpoint_set == false) {
                                unsigned long entry_address =
                                    get_entry_absolute_address(&dbg->dbgee);
                                if (entry_address == 0) {
                                        (void)(fprintf(
                                            stderr, COLOR_RED
                                            "Failed to retrieve the entry "
                                            "point.\n" COLOR_RESET));
                                        return EXIT_FAILURE;
                                }

                                if (set_temp_sw_breakpoint(&dbg->dbgee,
                                                           entry_address) !=
                                    EXIT_SUCCESS) {
                                        (void)(fprintf(
                                            stderr,
                                            COLOR_RED "Failed to set temporary "
                                                      "breakpoint at "
                                                      "0x%lx.\n" COLOR_RESET,
                                            entry_address));
                                        return EXIT_FAILURE;
                                }

                                if (ptrace(PTRACE_CONT, dbg->dbgee.pid, NULL,
                                           NULL) == -1) {
                                        perror("ptrace CONT after setting "
                                               "breakpoint");
                                        return EXIT_FAILURE;
                                }

                                entry_startup_breakpoint_set = true;
                                continue;
                        }

                        size_t sw_bp_index;
                        size_t hw_bp_index;
                        size_t cp_signal_index;
                        size_t wp_index;
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

                        if (is_watchpoint(&dbg->dbgee, &wp_index)) {
                                breakpoint_handled = true;
                                if (handle_watchpoint(&dbg->dbgee, wp_index) !=
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
                                        printf(
                                            COLOR_YELLOW
                                            "Ignoring event %lx.\n" COLOR_RESET,
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
                                // a breakpoint nor a single-step event, forward
                                // it back to the debuggee to counter
                                // anti-debugging techniques.
                                if (sig == SIGTRAP) {
                                        printf(COLOR_CYAN
                                               "[INFO] Sending SIGTRAP back to "
                                               "debuggee.\n" COLOR_RESET);
                                        if (ptrace(PTRACE_CONT, dbg->dbgee.pid,
                                                   NULL, SIGTRAP) == -1) {
                                                perror("ptrace CONT to send "
                                                       "SIGTRAP");
                                                return EXIT_FAILURE;
                                        }
                                        dbg->dbgee.state = RUNNING;
                                        continue;
                                }

                                printf(COLOR_YELLOW
                                       "Ignoring signal %d.\n" COLOR_RESET,
                                       sig);
                                if (ptrace(PTRACE_CONT, dbg->dbgee.pid, NULL,
                                           NULL) == -1) {
                                        perror("ptrace CONT to ignore signal");
                                        return EXIT_FAILURE;
                                }
                                dbg->dbgee.state = RUNNING;
                                continue;
                        }

                        if (read_and_handle_user_command(dbg) != EXIT_SUCCESS) {
                                return EXIT_FAILURE;
                        }
                }
        }

        return EXIT_SUCCESS;
}
