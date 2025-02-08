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

typedef struct {
        FILE *orig;
        FILE *logfile;
} tee_cookie;

void print_separator(void);
void print_separator_large(void);

FILE *create_tee_stream(const char *log_filename);
