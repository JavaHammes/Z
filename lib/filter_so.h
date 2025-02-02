#pragma once

#include <stdlib.h>

static const char *SO_FILES[] = {
    "libfopen_intercept.so", "libprctl_intercept.so", "libptrace_intercept.so",
    "libgetenv_intercept.so", NULL};
