#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum { SOFTWARE_BP, HARDWARE_BP, CATCHPOINT } breakpoint_t;

typedef struct {
        uintptr_t address;
        uint8_t original_byte;
        size_t size;
} software_breakpoint;

typedef struct {
        uintptr_t address;
} hardware_breakpoint;

typedef struct {
        int signal;
} catchpoint;

typedef union {
        software_breakpoint sw_bp;
        hardware_breakpoint hw_bp;
        catchpoint cp;
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
size_t add_catchpoint(breakpoint_handler *handler, int signal_number);
int remove_breakpoint(breakpoint_handler *handler, size_t index);
void list_breakpoints(const breakpoint_handler *handler);
void alloc_new_capacity(breakpoint_handler *handler);
