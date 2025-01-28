#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>

#define LOOP_COUNT 4

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

void check_for_debugging(void) {
        printf("To debug or not to debug?\n");

        if (try_to_debug_myself()) {
                printf("Am I flawed because I am observed,"
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
