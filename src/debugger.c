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
#include "ld_preload.h"
#include "ui.h"

static const char *_ptrace_event_name(unsigned long event) {
        switch (event) {
        case PTRACE_EVENT_FORK:
                return "PTRACE_EVENT_FORK";
        case PTRACE_EVENT_VFORK:
                return "PTRACE_EVENT_VFORK";
        case PTRACE_EVENT_CLONE:
                return "PTRACE_EVENT_CLONE";
        case PTRACE_EVENT_EXEC:
                return "PTRACE_EVENT_EXEC";
        case PTRACE_EVENT_VFORK_DONE:
                return "PTRACE_EVENT_VFORK_DONE";
        case PTRACE_EVENT_EXIT:
                return "PTRACE_EVENT_EXIT";
        default:
                return "UNKNOWN_EVENT";
        }
}

static int _add_default_preload_libraries(debugger *dbg) {
        char exe_path[PATH_MAX];
        ssize_t len =
            readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len == -1) {
                perror("readlink");
                return EXIT_FAILURE;
        }
        exe_path[len] = '\0';

        char *dir = dirname(exe_path);
        if (!dir) {
                perror("dirname");
                return EXIT_FAILURE;
        }

        const char *default_libs[] = {
            "libptrace_intercept.so", "libfopen_intercept.so",
            "libgetenv_intercept.so", "libprctl_intercept.so",
            "libsetvbuf_unbuffered.so"};
        size_t lib_count = sizeof(default_libs) / sizeof(default_libs[0]);

        for (size_t i = 0; i < lib_count; ++i) {
                char full_path[PATH_MAX];
                if ((unsigned long)snprintf(full_path, sizeof(full_path),
                                            "%s/%s", dir, default_libs[i]) >=
                    sizeof(full_path)) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Path too long for %s\n" COLOR_RESET,
                                       default_libs[i]));
                        return EXIT_FAILURE;
                }
                if (add_library(dbg->preload_list, full_path) != 0) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Failed to add library %s\n" COLOR_RESET,
                                       full_path));
                        return EXIT_FAILURE;
                }
        }
        return EXIT_SUCCESS;
}

static void _process_ld_preload_args(debugger *dbg, int argc, char **argv) {
        if (argc > 2) {
                for (int i = 2; i < argc; i++) {
                        const char *lib_path = argv[i];

                        if (add_library(dbg->preload_list, lib_path) !=
                            EXIT_SUCCESS) {
                                (void)(fprintf(stderr,
                                               COLOR_RED
                                               "Failed to add preload library: "
                                               "%s\n" COLOR_RESET,
                                               lib_path));
                        }
                }
        }

        if (dbg->preload_list->count == 0) {
                _add_default_preload_libraries(dbg);
        }
}

void init_debugger(debugger *dbg, const char *debuggee_name, int argc,
                   char **argv) {
        dbg->dbgee.pid = -1;
        dbg->dbgee.name = debuggee_name;
        dbg->dbgee.state = IDLE;
        dbg->dbgee.has_run = false;

        dbg->dbgee.bp_handler = init_breakpoint_handler();
        if (dbg->dbgee.bp_handler == NULL) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to initialize breakpoint handler.\n" COLOR_RESET));
                exit(EXIT_FAILURE);
        }

        dbg->preload_list = init_ld_preload_list();
        if (dbg->preload_list == NULL) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to initialize preload library "
                                         "list.\n" COLOR_RESET));
                free_breakpoint_handler(dbg->dbgee.bp_handler);
                exit(EXIT_FAILURE);
        }

        _process_ld_preload_args(dbg, argc, argv);
        dbg->state = DETACHED;
}

void free_debugger(debugger *dbg) {
        if (dbg->dbgee.state != TERMINATED) {
                if (kill(dbg->dbgee.pid, SIGKILL) == -1) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Failed to kill child with PID %d: "
                                       "%s\n" COLOR_RESET,
                                       dbg->dbgee.pid, strerror(errno)));
                }
        }

        dbg->dbgee.pid = -1;
        dbg->dbgee.state = TERMINATED;
        if (dbg->dbgee.bp_handler) {
                free_breakpoint_handler(dbg->dbgee.bp_handler);
                dbg->dbgee.bp_handler = NULL;
        }
        if (dbg->preload_list) {
                free_ld_preload_list(dbg->preload_list);
                dbg->preload_list = NULL;
        }
        dbg->state = DETACHED;
}

int start_debuggee(debugger *dbg) {
        pid_t pid = fork();
        if (pid == -1) {
                perror("fork");
                return EXIT_FAILURE;
        }

        if (pid == 0) {
                if (ld_preload_list_set_env(dbg->preload_list, NULL) != 0) {
                        (void)(fprintf(stderr, COLOR_RED
                                       "Failed to set LD_PRELOAD environment "
                                       "variable.\n" COLOR_RESET));
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
                        dbg->dbgee.state = STOPPED;

                        int sig = WSTOPSIG(status);
                        unsigned long event =
                            (status >> PTRACE_EVENT_SHIFT) & PTRACE_EVENT_MASK;

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
                                printf(
                                    COLOR_CYAN
                                    "Got ptrace event %lu (%s).\n" COLOR_RESET,
                                    event, _ptrace_event_name(event));

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

                        siginfo_t info; // NOLINT(misc-include-cleaner)
                        if (ptrace(PTRACE_GETSIGINFO, dbg->dbgee.pid, 0,
                                   &info) == -1) {
                                perror("ptrace(PTRACE_GETSIGINFO)");
                                return EXIT_FAILURE;
                        }

                        bool single_stepping =
                            info.si_code == 2 /* TRAP_TRACE */;
                        if (!single_stepping) {
                                if (!breakpoint_handled) {
                                        if (sig == SIGTRAP) {
                                                printf(
                                                    COLOR_CYAN
                                                    "[INFO] Sending SIGTRAP "
                                                    "back to "
                                                    "debuggee.\n" COLOR_RESET);
                                                (void)(fflush(stdout));
                                                if (ptrace(PTRACE_CONT,
                                                           dbg->dbgee.pid, NULL,
                                                           SIGTRAP) == -1) {
                                                        perror("ptrace CONT to "
                                                               "send SIGTRAP");
                                                        return EXIT_FAILURE;
                                                }
                                                dbg->dbgee.state = RUNNING;
                                                continue;
                                        }
                                        printf(
                                            COLOR_YELLOW
                                            "Ignoring signal %d.\n" COLOR_RESET,
                                            sig);
                                }
                        } else {
                                printf(
                                    COLOR_GREEN
                                    "Stepped one instruction.\n" COLOR_RESET);
                        }

                        if (read_and_handle_user_command(dbg) != EXIT_SUCCESS) {
                                return EXIT_FAILURE;
                        }
                }
        }

        return EXIT_SUCCESS;
}
