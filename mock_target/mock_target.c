#include <stdio.h>
#include <unistd.h>

int debug_count = 0;

void print_message(void) {
        printf("I debug, therefore I am.\n");
}

int main(void) {
        (void)(setvbuf(stdout, NULL, _IONBF, 0));

        printf("Mock target started with PID %d\n", getpid());

        int i = 3;
        while (i >= 0) {
                debug_count++;
                print_message();
                sleep(1);
                i--;
        }

        return 0;
}
