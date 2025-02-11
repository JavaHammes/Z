#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

void zZz(void) {}

__attribute__((constructor)) static void disable_stdout_buffering(void) {
        if (setvbuf(stdout, NULL, _IONBF, 0) != 0) {
                perror("setvbuf");
        }
}
