// NOLINTBEGIN
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <time.h>
#include <unistd.h>

#define LOOP_COUNT 4

int debug_count = 0;

static const char *blacklist[] = {
    "libfopen_intercept.so",    "libprctl_intercept.so",
    "libgetenv_intercept.so",   "libptrace_intercept.so",
    "libsetvbuf_unbuffered.so", NULL};

bool sigtrap_intercepted = false;

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

bool try_to_debug_myself(void) {
        return ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0;
}

bool timing_analysis(void) {
        clock_t start, end;

        start = clock();
        for (volatile int i = 0; i < 10000; i++)
                ;
        end = clock();

        return (double)((end - start) / CLOCKS_PER_SEC > 0.1);
}

bool check_for_additional_libraries(void) {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (!fp) {
                perror("fopen");
                return false;
        }

        char line[1024];
        while (fgets(line, sizeof(line), fp) != NULL) {
                for (int i = 0; blacklist[i] != NULL; i++) {
                        if (strstr(line, blacklist[i]) != NULL) {
                                fclose(fp);
                                return true;
                        }
                }
        }

        fclose(fp);
        return false;
}

bool check_ldpreload(void) {
        char *ld_preload = getenv("LD_PRELOAD");

        if (!ld_preload) {
                return false;
        }

        for (int i = 0; blacklist[i] != NULL; i++) {
                if (strstr(ld_preload, blacklist[i]) != NULL) {
                        return true;
                }
        }

        return false;
}

void check_for_debugging(void) {
        printf("To debug or not to debug?\n");

        bool debugging_detected = check_tracer_pid() || try_to_debug_myself() ||
                                  timing_analysis() ||
                                  check_for_additional_libraries() ||
                                  (!sigtrap_intercepted) || check_ldpreload();

        if (debugging_detected) {
                printf("Am I flawed because I am observed, "
                       "or dost thy observation create the flaw itself?\n");
        } else {
                printf("I am unwatched, unnoticed, untested. Is this freedom "
                       "or simply irrelevance?\n");
        }
}

void handler(int signo) {
        if (signo == SIGTRAP) {
                sigtrap_intercepted = true;
        }
}

void insert_false_breakpoint(void) {
        signal(SIGTRAP, handler);
        __asm__("int3");
}

int deny_memory_inspection(void) {
        if (prctl(PR_SET_DUMPABLE, 0, NULL, NULL) != 0) {
                perror("prctl");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

void init_anti_debug(void) {
        if (deny_memory_inspection() != EXIT_SUCCESS) {
                printf("They say a wise program hides its thoughts—clearly, I "
                       "am but a fool in the land of debuggers.\n");
        }

        insert_false_breakpoint();
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

int main(void) {
        init_anti_debug();
        check_for_debugging();

        int i = 3;
        while (i >= 0) {
                print_message();
                sleep(1);
                i--;
                increment_counter();
        }

        return EXIT_SUCCESS;
}
// NOLINTEND
