#include <stdio.h>
#include <unistd.h>

int main(void) {
        (void)(setvbuf(stdout, NULL, _IONBF, 0));

        printf("Mock target started with PID %d\n", getpid());

        int i = 3;
        while (i >= 0) {
                printf("I debug, therefore I am.\n");
                sleep(1);
                i--;
        }

        return 0;
}
