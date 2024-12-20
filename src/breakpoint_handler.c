#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "breakpoint_handler.h"

BreakpointHandler *init_breakpoint_handler(void) {
        BreakpointHandler *handler =
            (BreakpointHandler *)malloc(sizeof(BreakpointHandler));
        if (handler == NULL) {
                return NULL;
        }
        handler->breakpoints = NULL;
        handler->count = 0;
        handler->capacity = 0;
        return handler;
}

void free_breakpoint_handler(BreakpointHandler *handler) {
        free(handler->breakpoints);
        free(handler);
}

size_t add_software_breakpoint(BreakpointHandler *handler, uintptr_t address,
                               uint8_t originalData) {
        if (handler->count == handler->capacity) {
                size_t new_capacity =
                    (handler->capacity == 0) ? 4 : handler->capacity * 2;
                Breakpoint *new_breakpoints = realloc(
                    handler->breakpoints, new_capacity * sizeof(Breakpoint));
                if (!new_breakpoints) {
                        (void)(fprintf(stderr, "Error: Failed to allocate "
                                               "memory for breakpoints.\n"));
                        exit(EXIT_FAILURE);
                }
                handler->breakpoints = new_breakpoints;
                handler->capacity = new_capacity;
        }

        Breakpoint bp;
        bp.bp_t = SOFTWARE_BP;
        bp.data.sw_bp.address = address;
        bp.data.sw_bp.originalData = originalData;

        handler->breakpoints[handler->count++] = bp;

        return handler->count - 1;
}

size_t add_hardware_breakpoint(BreakpointHandler *handler, uintptr_t address) {
        if (handler->count == handler->capacity) {
                size_t new_capacity =
                    (handler->capacity == 0) ? 4 : handler->capacity * 2;
                Breakpoint *new_breakpoints = realloc(
                    handler->breakpoints, new_capacity * sizeof(Breakpoint));
                if (!new_breakpoints) {
                        (void)(fprintf(stderr, "Error: Failed to allocate "
                                               "memory for breakpoints.\n"));
                        exit(EXIT_FAILURE);
                }
                handler->breakpoints = new_breakpoints;
                handler->capacity = new_capacity;
        }

        Breakpoint bp;
        bp.bp_t = HARDWARE_BP;
        bp.data.hw_bp.address = address;

        handler->breakpoints[handler->count++] = bp;

        return handler->count - 1;
}

int remove_breakpoint(BreakpointHandler *handler, size_t index) {
        if (index >= handler->count) {
                (void)(fprintf(stderr,
                               "Error: Breakpoint index out of range.\n"));
                return -1;
        }

        memmove(&handler->breakpoints[index], &handler->breakpoints[index + 1],
                (handler->count - index - 1) * sizeof(Breakpoint));
        handler->count--;

        return 0;
}

void list_breakpoints(const BreakpointHandler *handler) {
        if (handler->count == 0) {
                printf("No breakpoints set.\n");
                return;
        }

        printf("Current Breakpoints:\n");
        printf("Idx\tType\t\tAddress\t\t\t");
        printf("Details\n");
        printf("---------------------------------------------------------------"
               "\n");

        for (size_t i = 0; i < handler->count; ++i) {
                printf("%zu\t", i);
                if (handler->breakpoints[i].bp_t == SOFTWARE_BP) {
                        printf("Software\t0x%lx\t\tOriginal Data: 0x%02X\n",
                               (unsigned long)handler->breakpoints[i]
                                   .data.sw_bp.address,
                               handler->breakpoints[i].data.sw_bp.originalData);
                } else if (handler->breakpoints[i].bp_t == HARDWARE_BP) {
                        printf("Hardware\t0x%lx\t\t\n",
                               (unsigned long)handler->breakpoints[i]
                                   .data.hw_bp.address);
                }
        }
}