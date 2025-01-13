#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
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

int main(void) {
        (void)(setvbuf(stdout, NULL, _IONBF, 0));

        printf("Mock target started with PID %d\n", getpid());

        (void)(raise(SIGSEGV));

        fork();

        int i = 3;
        while (i >= 0) {
                print_message();
                sleep(1);
                i--;
                increment_counter();
        }


        return 0;
}
