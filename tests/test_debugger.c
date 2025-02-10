// NOLINTBEGIN(misc-include-cleaner)

#include <unistd.h>

#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "debuggee.h"
#include "debugger.h"

#ifndef MOCK_DEBUGGEE_PATH
#define MOCK_DEBUGGEE_PATH "../bin/mock_target"
#endif

void redirect_all_stdout(void) {
        cr_redirect_stdout();
        cr_redirect_stderr();
}

Test(debugger, init_debugger_success) {
        debugger dbg;
        init_debugger(&dbg, MOCK_DEBUGGEE_PATH, 1, NULL);

        cr_assert_eq(dbg.dbgee.pid, -1);
        cr_assert_eq(dbg.dbgee.name, "../bin/mock_target");
        cr_assert_eq(dbg.dbgee.state, IDLE);
        cr_assert_eq(dbg.state, DETACHED);
}

Test(debugger, start_debuggee_success) {
        debugger dbg;
        init_debugger(&dbg, MOCK_DEBUGGEE_PATH, 0, NULL);

        int result = start_debuggee(&dbg);
        cr_assert_eq(result, 0, "start_debuggee failed with return value %d",
                     result);

        cr_assert_neq(dbg.dbgee.pid, -1, "Debuggee PID was not set.");
        cr_assert_eq(dbg.dbgee.state, RUNNING,
                     "Debuggee state flag not set to RUNNING.");

        free_debugger(&dbg);
}

Test(debugger, free_debugger_kill_running_debuggee,
     .init = redirect_all_stdout) {
        debugger dbg;
        init_debugger(&dbg, MOCK_DEBUGGEE_PATH, 0, NULL);

        int start_result = start_debuggee(&dbg);
        cr_assert_eq(start_result, 0,
                     "start_debuggee failed with return value %d",
                     start_result);

        free_debugger(&dbg);

        cr_assert_eq(dbg.dbgee.pid, -1,
                     "Debuggee PID should be reset after free_debugger.");
        cr_assert_eq(
            dbg.dbgee.state, TERMINATED,
            "Debuggee state flag should be TERMINATED after free_debugger.");
        cr_assert_eq(
            dbg.state, DETACHED,
            "Debugger state flag should be DETACHED after free_debugger.");
}

// NOLINTEND(misc-include-cleaner)
