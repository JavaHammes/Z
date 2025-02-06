#pragma once

#include <stdio.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_WHITE "\033[37m"

enum { LINE_LENGTH = 103 };

static inline void print_separator(void) {
        printf(COLOR_MAGENTA);
        for (int i = 0; i < LINE_LENGTH; i++) {
                putchar('-');
        }
        printf("\n" COLOR_RESET);
}

static inline void print_separator_large(void) {
        printf(COLOR_MAGENTA);
        for (int i = 0; i < LINE_LENGTH; i++) {
                putchar('=');
        }
        printf("\n" COLOR_RESET);
}
