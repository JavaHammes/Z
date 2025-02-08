#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ui.h"

static size_t strip_ansi(const char *src, size_t src_size, char *dst,
                         size_t dst_size) {
        size_t i = 0;
        size_t j = 0;
        enum { NORMAL, ESCAPE, CSI } state = NORMAL;

        while (i < src_size && j < dst_size - 1) {
                char c = src[i++];
                switch (state) {
                case NORMAL:
                        if (c == '\033') {
                                state = ESCAPE;
                        } else {
                                dst[j++] = c;
                        }
                        break;
                case ESCAPE:
                        if (c == '[') {
                                state = CSI;
                        } else {
                                if (j < dst_size - 2) {
                                        dst[j++] = '\033';
                                        dst[j++] = c;
                                }
                                state = NORMAL;
                        }
                        break;
                case CSI:
                        if (c >= '@' && c <= '~') {
                                state = NORMAL;
                        }
                        break;
                }
        }
        dst[j] = '\0';
        return j;
}

static ssize_t tee_write(void *cookie, const char *buf, size_t size) {
        tee_cookie *tc = (tee_cookie *)cookie;

        size_t written_console = fwrite(buf, 1, size, tc->orig);
        if (written_console != size) {
                return -1;
        }

        char *filtered = malloc(size + 1);
        if (!filtered) {
                return -1;
        }

        strip_ansi(buf, size, filtered, size + 1);

        size_t filtered_len = strlen(filtered);
        size_t written_file = fwrite(filtered, 1, filtered_len, tc->logfile);
        free(filtered);
        if (written_file != filtered_len) {
                return -1;
        }

        if (fflush(tc->orig) != 0) {
                return -1;
        }
        if (fflush(tc->logfile) != 0) {
                return -1;
        }

        return (ssize_t)size;
}

static int tee_close(void *cookie) {
        tee_cookie *tc = (tee_cookie *)cookie;
        int result = 0;
        if (tc->logfile) {
                result = fclose(tc->logfile);
                if (result != 0) {
                        perror("fclose(logfile)");
                }
        }
        free(tc);
        return result;
}

void print_separator(void) {
        printf(COLOR_MAGENTA);
        for (int i = 0; i < LINE_LENGTH; i++) {
                putchar('-');
        }
        printf("\n" COLOR_RESET);
}

void print_separator_large(void) {
        printf(COLOR_MAGENTA);
        for (int i = 0; i < LINE_LENGTH; i++) {
                putchar('=');
        }
        printf("\n" COLOR_RESET);
}

FILE *create_tee_stream(const char *log_filename) {
        FILE *log_file = fopen(log_filename, "w");
        if (log_file == NULL) {
                perror("fopen(log_filename)");
                return NULL;
        }

        tee_cookie *cookie = malloc(sizeof(tee_cookie));
        if (cookie == NULL) {
                perror("malloc(tee_cookie)");
                if (fclose(log_file) != 0) {
                        perror("fclose(log_file)");
                }
                return NULL;
        }
        cookie->orig = stdout;
        cookie->logfile = log_file;

        cookie_io_functions_t tee_funcs = {// NOLINT
                                           .read = NULL,
                                           .write = tee_write,
                                           .seek = NULL,
                                           .close = tee_close};

        FILE *new_stdout = fopencookie(cookie, "w", tee_funcs);
        if (new_stdout == NULL) {
                perror("fopencookie");
                free(cookie);
                if (fclose(log_file) != 0) {
                        perror("fclose(log_file)");
                }
                return NULL;
        }

        if (setvbuf(new_stdout, NULL, _IOLBF, 0) != 0) {
                perror("setvbuf");
                if (fclose(new_stdout) != 0) {
                        perror("fclose(new_stdout)");
                }
                return NULL;
        }

        return new_stdout;
}
