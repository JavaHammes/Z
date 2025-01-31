// NOLINTBEGIN
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <unistd.h>

#define LOOP_COUNT 4

int debug_count = 0;

unsigned long get_time_us() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (tv.tv_sec * 1000000) + tv.tv_usec;
}

void print_message(void) { printf("I debug, therefore I am.\n"); }

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

bool check_tracer_pid(void) {
        FILE *file = fopen("/proc/self/status", "r");
        if (!file) {
                return false;
        }

        char line[256];
        bool result = false;

        while (fgets(line, sizeof(line), file)) {
                if (strstr(line, "TracerPid:") != NULL) {
                        if (atoi(&line[10]) != 0) {
                                result = true;
                                break;
                        }
                }
        }

        (void)(fclose(file));
        return result;
}

bool try_to_debug_myself(void) { return ptrace(PTRACE_TRACEME, 0, 1, 0) < 0; }

bool timing_analysis(void) {
        unsigned long begin;
        unsigned long duration;

        begin = get_time_us();
        sleep(1);
        duration = get_time_us() - begin;

        return duration > 1010000;
}

void check_for_debugging(void) {
        printf("To debug or not to debug?\n");

        bool debugging_detected =
            check_tracer_pid() || try_to_debug_myself() || timing_analysis();

        if (debugging_detected) {
                printf("Am I flawed because I am observed, "
                       "or dost thy observation create the flaw itself?\n");
        } else {
                printf("I am unwatched, unnoticed, untested. Is this freedom "
                       "or simply irrelevance?\n");
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
// NOLINTEND
