// NOLINTBEGIN(misc-include-cleaner)

<<<<<<< HEAD
#include <unistd.h>
=======
#include "debuggee.h"
#include "debugger.h"
>>>>>>> d737422 (Introduction of a debuggee struct.)

#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "test_macros.h"

<<<<<<< HEAD
#include "debuggee.h"
#include "debugger.h"

=======
>>>>>>> d737422 (Introduction of a debuggee struct.)
#ifndef MOCK_DEBUGGEE_PATH
#define MOCK_DEBUGGEE_PATH "../bin/mock_target"
#endif

void redirect_all_stdout(void) {
        cr_redirect_stdout();
        cr_redirect_stderr();
}

<<<<<<< HEAD
static int stdin_pipe_fd[2];

void setup_stdin_pipe(void) {
        if (pipe(stdin_pipe_fd) == -1) {
                perror("pipe");
                exit(EXIT_FAILURE);
        }

        if (dup2(stdin_pipe_fd[0], STDIN_FILENO) == -1) {
                perror("dup2");
                exit(EXIT_FAILURE);
        }

        close(stdin_pipe_fd[0]);
}

Test(debugger, init_debugger_success) {
        debugger dbg;
        init_debugger(&dbg, MOCK_DEBUGGEE_PATH);

        cr_assert_eq(dbg.dbgee.pid, -1);
        cr_assert_eq(dbg.dbgee.name, "../bin/mock_target");
        cr_assert_eq(dbg.dbgee.state, IDLE);
        cr_assert_eq(dbg.state, DETACHED);
}

Test(debugger, start_debuggee_success) {
        debugger dbg;
        init_debugger(&dbg, MOCK_DEBUGGEE_PATH);

=======
Test(debugger, start_debuggee_success) {
        debugger dbg;
        init_dbg(&dbg, MOCK_DEBUGGEE_PATH);

>>>>>>> d737422 (Introduction of a debuggee struct.)
        int result = start_debuggee(&dbg);
        cr_assert_eq(result, 0, "start_debuggee failed with return value %d",
                     result);

        cr_assert_neq(dbg.dbgee.pid, -1, "Debuggee PID was not set.");
        cr_assert_eq(dbg.dbgee.state, RUNNING,
                     "Debuggee state flag not set to RUNNING.");

        free_debugger(&dbg);
}

<<<<<<< HEAD
Test(debugger, trace_debuggee_success, .init = setup_stdin_pipe) {
        debugger dbg;
        init_debugger(&dbg, MOCK_DEBUGGEE_PATH);
=======
Test(debugger, trace_debuggee_success, .init = redirect_all_stdout) {
        debugger dbg;
        init_dbg(&dbg, MOCK_DEBUGGEE_PATH);
>>>>>>> d737422 (Introduction of a debuggee struct.)

        int start_result = start_debuggee(&dbg);
        cr_assert_eq(start_result, 0,
                     "start_debuggee failed with return value %d",
                     start_result);

<<<<<<< HEAD
        const char *input = "run\n";
        ssize_t bytes_written = write(stdin_pipe_fd[1], input, strlen(input));
        cr_assert_eq(bytes_written, (ssize_t)strlen(input),
                     "Failed to write to stdin");

=======
>>>>>>> d737422 (Introduction of a debuggee struct.)
        int trace_result = trace_debuggee(&dbg);
        cr_assert_eq(trace_result, 0,
                     "trace_debuggee failed with return value %d",
                     trace_result);

        cr_assert_eq(
            dbg.state, DETACHED,
            "Debugger state should be DETACHED after running trace_debuggee.");
        cr_assert_eq(
            dbg.dbgee.state, TERMINATED,
            "Debuggee state should be TERMINATED after trace_debuggee.");

        free_debugger(&dbg);
}

<<<<<<< HEAD
Test(debugger, free_debugger_kill_running_debuggee,
     .init = redirect_all_stdout) {
        debugger dbg;
        init_debugger(&dbg, MOCK_DEBUGGEE_PATH);
=======
Test(debugger, free_dbg_kill_running_debuggee, .init = redirect_all_stdout) {
        debugger dbg;
        init_dbg(&dbg, MOCK_DEBUGGEE_PATH);
>>>>>>> d737422 (Introduction of a debuggee struct.)

        int start_result = start_debuggee(&dbg);
        cr_assert_eq(start_result, 0,
                     "start_debuggee failed with return value %d",
                     start_result);

        free_debugger(&dbg);

        cr_assert_eq(dbg.dbgee.pid, -1,
<<<<<<< HEAD
                     "Debuggee PID should be reset after free_debugger.");
        cr_assert_eq(
            dbg.dbgee.state, TERMINATED,
            "Debuggee state flag should be TERMINATED after free_debugger.");
        cr_assert_eq(
            dbg.state, DETACHED,
            "Debugger state flag should be DETACHED after free_debugger.");
=======
                     "Debuggee PID should be reset after free_dbg.");
        cr_assert_eq(
            dbg.dbgee.state, TERMINATED,
            "Debuggee state flag should be TERMINATED after free_dbg.");
        cr_assert_eq(dbg.state, DETACHED,
                     "Debugger state flag should be DETACHED after free_dbg.");
>>>>>>> d737422 (Introduction of a debuggee struct.)
}

// NOLINTEND(misc-include-cleaner)
