#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "breakpoint_handler.h"

breakpoint_handler *init_breakpoint_handler(void) {
        breakpoint_handler *handler =
            (breakpoint_handler *)malloc(sizeof(breakpoint_handler));
        if (handler == NULL) {
                return NULL;
        }
        handler->breakpoints = NULL;
        handler->count = 0;
        handler->capacity = 0;
        return handler;
}

void free_breakpoint_handler(breakpoint_handler *handler) {
        free(handler->breakpoints);
        free(handler);
}

size_t add_software_breakpoint(breakpoint_handler *handler, uintptr_t address,
                               uint8_t original_byte) {
        if (handler->count == handler->capacity) {
                alloc_new_capacity(handler);
        }

        breakpoint bp;
        bp.bp_t = SOFTWARE_BP;
        bp.data.sw_bp.address = address;
        bp.data.sw_bp.original_byte = original_byte;
        bp.temporary = false;

        handler->breakpoints[handler->count++] = bp;

        return handler->count - 1;
}

size_t add_hardware_breakpoint(breakpoint_handler *handler, uintptr_t address) {
        if (handler->count == handler->capacity) {
                alloc_new_capacity(handler);
        }

        breakpoint bp;
        bp.bp_t = HARDWARE_BP;
        bp.data.hw_bp.address = address;
        bp.temporary = false;

        handler->breakpoints[handler->count++] = bp;

        return handler->count - 1;
}

size_t add_catchpoint_signal(breakpoint_handler *handler, int signal_number) {
        if (handler->count == handler->capacity) {
                alloc_new_capacity(handler);
        }

        breakpoint bp;
        bp.bp_t = CATCHPOINT_SIGNAL;
        bp.data.cp_signal.signal = signal_number;
        bp.temporary = false;

        handler->breakpoints[handler->count++] = bp;

        return handler->count - 1;
}

size_t add_catchpoint_event(breakpoint_handler *handler,
                            const char *event_name) {
        if (handler->count == handler->capacity) {
                alloc_new_capacity(handler);
        }

        breakpoint_t bp_type = CATCHPOINT_EVENT_INVALID;
        if (strcmp(event_name, "fork") == 0) {
                bp_type = CATCHPOINT_EVENT_FORK;
        } else if (strcmp(event_name, "vfork") == 0) {
                bp_type = CATCHPOINT_EVENT_VFORK;
        } else if (strcmp(event_name, "clone") == 0) {
                bp_type = CATCHPOINT_EVENT_CLONE;
        } else if (strcmp(event_name, "exec") == 0) {
                bp_type = CATCHPOINT_EVENT_EXEC;
        } else if (strcmp(event_name, "exit") == 0) {
                bp_type = CATCHPOINT_EVENT_EXIT;
        }

        for (size_t i = 0; i < handler->count; ++i) {
                breakpoint *bp = &handler->breakpoints[i];
                if (bp != NULL && bp->bp_t == bp_type) {
                        (void)(fprintf(stderr,
                                       "Error: A catchpoint for event '%s' "
                                       "already exists at index %zu.\n",
                                       event_name, i));
                        return (size_t)-1;
                }
        }

        breakpoint bp;
        bp.bp_t = bp_type;
        strncpy(bp.data.cp_event.event_name, event_name,
                sizeof(bp.data.cp_event.event_name) - 1);
        bp.data.cp_event.event_name[sizeof(bp.data.cp_event.event_name) - 1] =
            '\0';
        bp.temporary = false;

        handler->breakpoints[handler->count++] = bp; // NOLINT

        return handler->count - 1;
}

int remove_breakpoint(breakpoint_handler *handler, size_t index) {
        if (index >= handler->count) {
                (void)(fprintf(stderr,
                               "Error: breakpoint index out of range.\n"));
                return -1;
        }

        memmove(&handler->breakpoints[index], &handler->breakpoints[index + 1],
                (handler->count - index - 1) * sizeof(breakpoint));
        handler->count--;

        return 0;
}

void list_breakpoints(const breakpoint_handler *handler) {
        if (handler->count == 0) {
                printf("No breakpoints set.\n");
                return;
        }

        printf("Current breakpoints and catchpoints:\n");
        printf("Idx\tType\t\tAddress\t\t\tDetails\n");
        printf("---------------------------------------------------------------"
               "\n");

        for (size_t i = 0; i < handler->count; ++i) {
                printf("%zu\t", i);
                switch (handler->breakpoints[i].bp_t) {
                case SOFTWARE_BP:
                        printf(
                            "Software\t0x%lx\t\tOriginal Data: 0x%02X\n",
                            (unsigned long)handler->breakpoints[i]
                                .data.sw_bp.address,
                            handler->breakpoints[i].data.sw_bp.original_byte);
                        break;

                case HARDWARE_BP:
                        printf("Hardware\t0x%lx\t\t\n",
                               (unsigned long)handler->breakpoints[i]
                                   .data.hw_bp.address);
                        break;

                case CATCHPOINT_SIGNAL:
                        printf("Catchpoint\t-\t\tSignal: %d\n",
                               handler->breakpoints[i].data.cp_signal.signal);
                        break;

                case CATCHPOINT_EVENT_FORK:
                case CATCHPOINT_EVENT_VFORK:
                case CATCHPOINT_EVENT_CLONE:
                case CATCHPOINT_EVENT_EXEC:
                case CATCHPOINT_EVENT_EXIT:
                        printf(
                            "Catchpoint\t-\t\tEvent: %s\n",
                            handler->breakpoints[i].data.cp_event.event_name);
                        break;

                default:
                        printf("Unknown\t\t-\t\t-\n");
                        break;
                }
        }
}

void alloc_new_capacity(breakpoint_handler *handler) {
        size_t new_capacity =
            (handler->capacity == 0) ? 4 : handler->capacity * 2;
        breakpoint *new_breakpoints =
            realloc(handler->breakpoints, new_capacity * sizeof(breakpoint));

        if (!new_breakpoints) {
                (void)(fprintf(stderr, "Error: Failed to allocate "
                                       "memory for breakpoints.\n"));
                exit(EXIT_FAILURE);
        }

        handler->breakpoints = new_breakpoints;
        handler->capacity = new_capacity;
}
