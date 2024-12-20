#include <stdint.h>
#include <stdio.h>

typedef enum { SOFTWARE_BP, HARDWARE_BP } breakpoint_t;

typedef struct {
        uintptr_t address;    /**< Address where the breakpoint is set */
        uint8_t originalData; /**< Original data at the breakpoint address */
} SoftwareBreakpoint;

typedef struct {
        uintptr_t address; /**< Address where the breakpoint is set */
} HardwareBreakpoint;

typedef union {
        SoftwareBreakpoint sw_bp;
        HardwareBreakpoint hw_bp;
} BreakpointData;

typedef struct {
        breakpoint_t bp_t;   /**< Type of the breakpoint */
        BreakpointData data; /**< Data of the breakpoint */
} Breakpoint;

typedef struct {
        Breakpoint *breakpoints; /**< Dynamic array of breakpoints */
        size_t count;            /**< Current number of breakpoints */
        size_t capacity;         /**< Allocated capacity */
} BreakpointHandler;

BreakpointHandler *init_breakpoint_handler(void);
void free_breakpoint_handler(BreakpointHandler *handler);
size_t add_software_breakpoint(BreakpointHandler *handler, uintptr_t address,
                               uint8_t originalData);
size_t add_hardware_breakpoint(BreakpointHandler *handler, uintptr_t address);
int remove_breakpoint(BreakpointHandler *handler, size_t index);
void list_breakpoints(const BreakpointHandler *handler);
