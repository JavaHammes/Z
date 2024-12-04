// NOLINTBEGIN(misc-include-cleaner)

#include "debuggee.h"
#include "debugger.h"

#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "test_macros.h"

#ifndef MOCK_DEBUGGEE_PATH
#define MOCK_DEBUGGEE_PATH "../bin/mock_target"
#endif

void redirect_all_stdout(void) {
        cr_redirect_stdout();
        cr_redirect_stderr();
}

Test(debugger, start_debuggee_success) {
        debugger dbg;
        init_dbg(&dbg, MOCK_DEBUGGEE_PATH);

        int result = start_debuggee(&dbg);
        cr_assert_eq(result, 0, "start_debuggee failed with return value %d",
                     result);

        cr_assert_neq(dbg.dbgee.pid, -1, "Debuggee PID was not set.");
        cr_assert_eq(dbg.dbgee.state, RUNNING,
                     "Debuggee state flag not set to RUNNING.");

        free_dbg(&dbg);
}

Test(debugger, trace_debuggee_success, .init = redirect_all_stdout) {
        debugger dbg;
        init_dbg(&dbg, MOCK_DEBUGGEE_PATH);

        int start_result = start_debuggee(&dbg);
        cr_assert_eq(start_result, 0,
                     "start_debuggee failed with return value %d",
                     start_result);

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

        free_dbg(&dbg);
}

Test(debugger, free_dbg_kill_running_debuggee, .init = redirect_all_stdout) {
        debugger dbg;
        init_dbg(&dbg, MOCK_DEBUGGEE_PATH);

        int start_result = start_debuggee(&dbg);
        cr_assert_eq(start_result, 0,
                     "start_debuggee failed with return value %d",
                     start_result);

        free_dbg(&dbg);

        cr_assert_eq(dbg.dbgee.pid, -1,
                     "Debuggee PID should be reset after free_dbg.");
        cr_assert_eq(
            dbg.dbgee.state, TERMINATED,
            "Debuggee state flag should be TERMINATED after free_dbg.");
        cr_assert_eq(dbg.state, DETACHED,
                     "Debugger state flag should be DETACHED after free_dbg.");
}

// NOLINTEND(misc-include-cleaner)
