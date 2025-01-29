#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum {
        EVENT_NAME_SIZE = 16,
};

typedef enum {
        SOFTWARE_BP,
        HARDWARE_BP,
        CATCHPOINT_SIGNAL,
        CATCHPOINT_EVENT_FORK,
        CATCHPOINT_EVENT_VFORK,
        CATCHPOINT_EVENT_CLONE,
        CATCHPOINT_EVENT_EXEC,
        CATCHPOINT_EVENT_EXIT,
        CATCHPOINT_EVENT_INVALID,
        WATCHPOINT,
} breakpoint_t;

typedef struct {
        uintptr_t address;
        uint8_t original_byte;
        size_t size;
} software_breakpoint;

typedef struct {
        uintptr_t address;
} hardware_breakpoint;

typedef struct {
        uintptr_t address;
} watchpoint;

typedef struct {
        int signal;
} catchpoint_signal;

typedef struct {
        char event_name[EVENT_NAME_SIZE];
} catchpoint_event;

typedef union {
        software_breakpoint sw_bp;
        hardware_breakpoint hw_bp;
        catchpoint_signal cp_signal;
        catchpoint_event cp_event;
        watchpoint wp;
} breakpoint_data;

typedef struct {
        breakpoint_t bp_t;
        breakpoint_data data;
        bool temporary;
} breakpoint;

typedef struct {
        breakpoint *breakpoints;
        size_t count;
        size_t capacity;
} breakpoint_handler;

breakpoint_handler *init_breakpoint_handler(void);
void free_breakpoint_handler(breakpoint_handler *handler);
size_t add_software_breakpoint(breakpoint_handler *handler, uintptr_t address,
                               uint8_t original_byte);
size_t add_hardware_breakpoint(breakpoint_handler *handler, uintptr_t address);
size_t add_watchpoint(breakpoint_handler *handler, uintptr_t address);
size_t add_catchpoint_signal(breakpoint_handler *handler, int signal_number);
size_t add_catchpoint_event(breakpoint_handler *handler, const char *event);
int remove_breakpoint(breakpoint_handler *handler, size_t index);
void list_breakpoints(const breakpoint_handler *handler);
