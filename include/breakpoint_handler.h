#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum { SOFTWARE_BP, HARDWARE_BP } breakpoint_t;

typedef struct {
        uintptr_t address;     /**< Address where the breakpoint is set */
        uint8_t original_byte; /**< Original data at the breakpoint address */
        size_t size;
} software_breakpoint;

typedef struct {
        uintptr_t address; /**< Address where the breakpoint is set */
} hardware_breakpoint;

typedef union {
        software_breakpoint sw_bp;
        hardware_breakpoint hw_bp;
} breakpoint_data;

typedef struct {
        breakpoint_t bp_t;    /**< Type of the breakpoint */
        breakpoint_data data; /**< Data of the breakpoint */
        bool temporary;
} breakpoint;

typedef struct {
        breakpoint *breakpoints; /**< Dynamic array of breakpoints */
        size_t count;            /**< Current number of breakpoints */
        size_t capacity;         /**< Allocated capacity */
} breakpoint_handler;

breakpoint_handler *init_breakpoint_handler(void);
void free_breakpoint_handler(breakpoint_handler *handler);
size_t add_software_breakpoint(breakpoint_handler *handler, uintptr_t address,
                               uint8_t original_byte);
size_t add_hardware_breakpoint(breakpoint_handler *handler, uintptr_t address);
int remove_breakpoint(breakpoint_handler *handler, size_t index);
void list_breakpoints(const breakpoint_handler *handler);
