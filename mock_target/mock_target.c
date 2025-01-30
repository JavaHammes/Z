#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

#define LOOP_COUNT 4
#define MAX_LINE_LENGTH 256
#define DECIMAL_BASE 10
#define TEN_CHARS 10

int debug_count = 0;

void print_message(void) {
        printf("I debug, therefore I am.\n");
}

void sub_method(void) {
        int j = 1;
        for (int i = 0; i < LOOP_COUNT; i++) {
                j++;
        }
        debug_count += j;
}

void increment_counter(void) {
        debug_count++;
        sub_method();
}

bool try_to_debug_myself(void) {
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
                return true;
        }
        return false;
}

bool check_tracer_pid(void) {
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) {
        return false;
    }

    char line[MAX_LINE_LENGTH];
    bool result = false;

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "TracerPid:", DECIMAL_BASE) == 0) {
            int tracer_pid = 0;
            if (sscanf(line + TEN_CHARS, "%d", &tracer_pid) == 1 && tracer_pid != 0) { // NOLINT
                result = true;
                break;
            }
        }
    }

    (void)(fclose(file));
    return result;
}

void check_for_debugging(void) {
        printf("To debug or not to debug?\n");

        bool debugging_detected = try_to_debug_myself() || check_tracer_pid();

        if (debugging_detected) {
                printf("Am I flawed because I am observed, "
                       "or dost thy observation create the flaw itself?\n");
        } else {
                printf("I am unwatched, unnoticed, untested. Is this freedom or simply irrelevance?\n");
        }
}

int main(void) {
        (void)(setvbuf(stdout, NULL, _IONBF, 0));

        check_for_debugging();

        int i = 3;
        while (i >= 0) {
                print_message();
                sleep(1);
                i--;
                increment_counter();
        }


        return 0;
}
