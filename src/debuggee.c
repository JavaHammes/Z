#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "colors.h"
#include "debuggee.h"

#define DR0_OFFSET offsetof(struct user, u_debugreg[0])
#define DR1_OFFSET offsetof(struct user, u_debugreg[1])
#define DR2_OFFSET offsetof(struct user, u_debugreg[2])
#define DR3_OFFSET offsetof(struct user, u_debugreg[3])
#define DR6_OFFSET offsetof(struct user, u_debugreg[6])
#define DR7_OFFSET offsetof(struct user, u_debugreg[7])

enum {
        DUMP_SIZE = 128,
        ASCII_PRINTABLE_MIN = 32,
        ASCII_PRINTABLE_MAX = 126,
        WORD_LENGTH = 16,
        BYTE_LENGTH = 8,
        MAX_BYTE_VALUE = 0xFF,
        RESPONSE_BUFFER_SIZE = 10,
        DECIMAL_BASE_PARAMETER = 10,
        BYTE_MASK = 0xFFUL,
        INDEX_STR_MAX_LEN = 20,
        DR7_ENABLE_MASK = 0xF,
        DR7_MASK_RW_BITS = 0x3,
        DR7_MASK_LEN_BITS = 0x3,
        DR7_RW_BASE_SHIFT = 16,
        DR7_LEN_BASE_SHIFT = 18,
        INT3_OPCODE = 0xCC,
        MAX_X86_INSTRUCT_LEN = 15,
        NEXT_INSTRUCTION_OFFSET = 5,
        MODULE_NAME_SIZE = 256,
        LINE_BUFFER_SIZE = 512,
        HEX_BASE = 16,
        PERMS_SIZE = 5,
        DEV_SIZE = 6,
        PATHNAME_SIZE = 256,
        NUM_ITEMS_THRESHOLD = 7,
        WATCHPOINT_RW_READ_WRITE = 0x3,
        WATCHPOINT_LEN_1_BYTE = 0x0,
        WATCHPOINT_LEN_2_BYTES = 0x1,
        WATCHPOINT_LEN_4_BYTES = 0x3,
        WATCHPOINT_LEN_8_BYTES = 0x2,
        NSIG = 31,
        LOWER_FOUR_BYTES_MASK = 0xF,
};

static inline unsigned long DR7_ENABLE_LOCAL(int bpno) {
        return 0x1UL << (bpno * 2);
}

static inline unsigned long DR7_RW_SHIFT(int bpno) {
        return (DR7_RW_BASE_SHIFT + bpno * 4);
}

static inline unsigned long DR7_LEN_SHIFT(int bpno) {
        return (DR7_LEN_BASE_SHIFT + bpno * 4);
}

static bool should_remove_breakpoints(const debuggee *dbgee) {
        printf(COLOR_YELLOW "There are %zu breakpoints set. Do you want to "
                            "remove all breakpoints and run until termination? "
                            "(y/N): " COLOR_RESET,
               dbgee->bp_handler->count);

        char response[RESPONSE_BUFFER_SIZE];
        if (fgets(response, sizeof(response), stdin) != NULL) {
                size_t i = 0;
                while (isspace((unsigned char)response[i])) {
                        i++;
                }
                char answer = (char)tolower((unsigned char)response[i]);

                if (answer != 'y') {
                        return false;
                }
        }

        return true;
}

static bool _is_valid_address(debuggee *dbgee, unsigned long addr) {
        char maps_path[MODULE_NAME_SIZE];
        (void)(snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps",
                        dbgee->pid));

        FILE *maps = fopen(maps_path, "r");
        if (!maps) {
                perror("fopen /proc/<pid>/maps");
                return false;
        }

        char line[LINE_BUFFER_SIZE];
        bool valid = false;

        while (fgets(line, sizeof(line), maps)) {
                unsigned long start;
                unsigned long end;
                char perms[PERMS_SIZE];
                if (sscanf(line, "%lx-%lx %4s", // NOLINT
                           &start, &end, perms) != 3) {
                        continue;
                }

                if (addr >= start && addr < end) {
                        if (strchr(perms, 'x') != NULL ||
                            strchr(perms, 'r') != NULL ||
                            strchr(perms, 'w') != NULL) {
                                valid = true;
                        }
                        break;
                }
        }

        (void)(fclose(maps));
        return valid;
}

static int _read_memory(pid_t pid, unsigned long address, unsigned char *buf,
                        size_t size) {
        size_t i = 0;
        long word;
        errno = 0;

        while (i < size) {
                word = ptrace(PTRACE_PEEKDATA, pid, address + i, NULL);
                if (word == -1 && errno != 0) {
                        perror("ptrace PEEKDATA");
                        return EXIT_FAILURE;
                }

                size_t j;
                for (j = 0; j < sizeof(long) && i < size; j++, i++) {
                        buf[i] = (word >> (BYTE_LENGTH * j)) & MAX_BYTE_VALUE;
                }
        }

        return EXIT_SUCCESS;
}

static int _read_debug_register(pid_t pid, unsigned long offset,
                                unsigned long *value) {
        errno = 0;
        *value = ptrace(PTRACE_PEEKUSER, pid, offset, NULL);
        if (*value == (unsigned long)-1 && errno != 0) {
                perror("ptrace PEEKUSER debug register");
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

static int _set_debug_register(pid_t pid, unsigned long offset,
                               unsigned long value) {
        if (ptrace(PTRACE_POKEUSER, pid, offset, value) == -1) {
                perror("ptrace POKEUSER DR7");
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

static int _configure_dr7(pid_t pid, int bpno, int condition, int length,
                          bool enable) {
        unsigned long dr7;

        if (_read_debug_register(pid, DR7_OFFSET, &dr7) != 0) {
                return EXIT_FAILURE;
        }

        if (enable) {
                dr7 |= DR7_ENABLE_LOCAL(bpno);
                dr7 &= ~(DR7_ENABLE_MASK << DR7_RW_SHIFT(bpno));
                dr7 |= (condition & DR7_MASK_RW_BITS) << DR7_RW_SHIFT(bpno);
                dr7 |= (length & DR7_MASK_LEN_BITS) << DR7_LEN_SHIFT(bpno);
        } else {
                dr7 &= ~(DR7_ENABLE_MASK << DR7_RW_SHIFT(bpno));
        }

        return _set_debug_register(pid, DR7_OFFSET, dr7);
}

static int _remove_all_breakpoints(debuggee *dbgee) {
        while (dbgee->bp_handler->count > 0) {
                size_t last_index = dbgee->bp_handler->count - 1;
                char index_str[INDEX_STR_MAX_LEN];

                if (snprintf(index_str, sizeof(index_str), "%zu", last_index) <
                    0) {
                        (void)(fprintf(stderr,
                                       COLOR_RED "Failed to format breakpoint "
                                                 "index.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }

                if (RemoveBreakpoint(dbgee, index_str) != EXIT_SUCCESS) {
                        (void)(fprintf(stderr,
                                       COLOR_RED "Failed to remove breakpoint "
                                                 "at index %zu.\n" COLOR_RESET,
                                       last_index));
                        return EXIT_FAILURE;
                }
        }
        return EXIT_SUCCESS;
}

static bool _breakpoint_exists(const debuggee *dbgee, unsigned long address) {
        for (size_t i = 0; i < dbgee->bp_handler->count; ++i) {
                breakpoint *bp = &dbgee->bp_handler->breakpoints[i];
                if (bp->bp_t == SOFTWARE_BP &&
                    bp->data.sw_bp.address == address) {
                        return true;
                }
                if (bp->bp_t == HARDWARE_BP &&
                    bp->data.hw_bp.address == address) {
                        return true;
                }
        }
        return false;
}

static bool _is_call_instruction(debuggee *dbgee, unsigned long rip) {
        unsigned char buf[MAX_X86_INSTRUCT_LEN];
        if (_read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to read memory at 0x%lx for "
                                         "instruction check.\n" COLOR_RESET,
                               rip));
                return false;
        }

        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to initialize Capstone for "
                                         "instruction check.\n" COLOR_RESET));
                return false;
        }

        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        count = cs_disasm(handle, buf, sizeof(buf), rip, 1, &insn);
        if (count > 0) {
                bool is_call = false;
                if (insn[0].id == X86_INS_CALL) {
                        is_call = true;
                }
                cs_free(insn, count);
                cs_close(&handle);
                return is_call;
        }

        cs_close(&handle);
        return false;
}

static unsigned long _get_load_base(debuggee *dbgee) {
        char maps_path[MODULE_NAME_SIZE];
        (void)(snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps",
                        dbgee->pid));

        FILE *maps = fopen(maps_path, "r");
        if (!maps) {
                perror("fopen maps");
                return 0;
        }

        char line[LINE_BUFFER_SIZE];
        unsigned long base_address = 0;

        while (fgets(line, sizeof(line), maps)) {

                // Each line has the format:
                // address           perms offset  dev   inode      pathname
                if (strstr(line, dbgee->name)) {
                        char *dash = strchr(line, '-');
                        if (!dash) {
                                continue;
                        }
                        *dash = '\0';
                        base_address = strtoul(line, NULL, HEX_BASE);
                        break;
                }
        }

        (void)(fclose(maps));

        if (base_address == 0) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to find base address for %s "
                                         "in pid %d.\n" COLOR_RESET,
                               dbgee->name, dbgee->pid));
        }

        return base_address;
}

static unsigned long _get_module_base_address(pid_t pid, unsigned long rip,
                                              char *module_name,
                                              size_t module_name_size) {
        char maps_path[MODULE_NAME_SIZE];
        (void)(snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid));

        FILE *maps = fopen(maps_path, "r");
        if (!maps) {
                perror("fopen maps");
                return 0;
        }

        char line[LINE_BUFFER_SIZE];
        unsigned long base_address = 0;
        module_name[0] = '\0';

        while (fgets(line, sizeof(line), maps)) {
                unsigned long start;
                unsigned long end;
                char perms[PERMS_SIZE];
                unsigned long offset;
                char dev[DEV_SIZE];
                unsigned long inode;
                char pathname[PATHNAME_SIZE] = {0};

                int num_items = sscanf( // NOLINT(cert-err34-c)
                    line, "%lx-%lx %4s %lx %5s %lu %s", &start, &end, perms,
                    &offset, dev, &inode, pathname);

                if (rip >= start && rip < end) {
                        base_address = start;
                        if (num_items >= NUM_ITEMS_THRESHOLD) {
                                strncpy(module_name, pathname,
                                        module_name_size - 1);
                                module_name[module_name_size - 1] = '\0';
                        } else {
                                strncpy(module_name, "[anonymous]",
                                        module_name_size - 1);
                                module_name[module_name_size - 1] = '\0';
                        }
                        break;
                }
        }

        (void)(fclose(maps));

        if (base_address == 0) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Failed to find base address containing RIP "
                               "0x%lx in pid %d.\n" COLOR_RESET,
                               rip, pid));
        }

        return base_address;
}

static unsigned long _get_symbol_offset(debuggee *dbgee,
                                        const char *symbol_name) {
        if (symbol_name == NULL) {
                (void)(fprintf(stderr, COLOR_RED
                               "Symbol name cannot be NULL.\n" COLOR_RESET));
                return 0;
        }

        elf_symtab symtab_struct;
        if (!read_elf_symtab(dbgee->name, &symtab_struct)) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to read ELF symbol tables.\n" COLOR_RESET));
                return 0;
        }

        unsigned long symbol_offset = 0;
        bool found = false;

        for (size_t entry_idx = 0; entry_idx < symtab_struct.num_entries;
             entry_idx++) {
                elf_symtab_entry *entry = &symtab_struct.entries[entry_idx];
                for (size_t j = 0; j < entry->num_symbols; j++) {
                        Elf64_Sym sym = entry->symtab[j];
                        const char *sym_name = entry->strtab + sym.st_name;

                        if (strcmp(sym_name, symbol_name) == 0) {
                                symbol_offset = sym.st_value;
                                found = true;
                                break;
                        }
                }
                if (found) {
                        break;
                }
        }

        if (!found) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "'%s' symbol not found in %s.\n" COLOR_RESET,
                               symbol_name, dbgee->name));
        }

        for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                free(symtab_struct.entries[i].symtab);
                free(symtab_struct.entries[i].strtab);
        }
        free(symtab_struct.entries);

        return symbol_offset;
}

static int _step_and_wait(debuggee *dbgee) { // NOLINT
        if (Step(dbgee) != EXIT_SUCCESS) {
                (void)(fprintf(stderr, COLOR_RED
                               "Failed to single step.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        int status;
        if (waitpid(dbgee->pid, &status, 0) == -1) {
                perror("waitpid");
                return EXIT_FAILURE;
        }

        if (WIFEXITED(status)) {
                printf(COLOR_YELLOW
                       "Debuggee %d exited with status %d.\n" COLOR_RESET,
                       dbgee->pid, WEXITSTATUS(status));
                dbgee->state = TERMINATED;
                return EXIT_FAILURE;
        }

        if (WIFSIGNALED(status)) {
                printf(COLOR_YELLOW
                       "Debuggee %d was killed by signal %d.\n" COLOR_RESET,
                       dbgee->pid, WTERMSIG(status));
                dbgee->state = TERMINATED;
                return EXIT_FAILURE;
        }

        if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                unsigned long event =
                    (status >> PTRACE_EVENT_SHIFT) & PTRACE_EVENT_MASK;

                size_t sw_bp_index;
                size_t hw_bp_index;
                size_t cp_signal_index;
                bool breakpoint_handled = false;

                if (is_software_breakpoint(dbgee, &sw_bp_index)) {
                        breakpoint_handled = true;
                        if (handle_software_breakpoint(dbgee, sw_bp_index) !=
                            EXIT_SUCCESS) {
                                return EXIT_FAILURE;
                        }
                }

                if (is_hardware_breakpoint(dbgee, &hw_bp_index)) {
                        breakpoint_handled = true;
                        if (handle_hardware_breakpoint(dbgee, hw_bp_index) !=
                            EXIT_SUCCESS) {
                                return EXIT_FAILURE;
                        }
                }

                if (is_catchpoint_signal(dbgee, &cp_signal_index, sig)) {
                        breakpoint_handled = true;
                        if (handle_catchpoint_signal(dbgee, cp_signal_index) !=
                            EXIT_SUCCESS) {
                                return EXIT_FAILURE;
                        }
                }

                if (event != 0) {
                        size_t cp_event_index;
                        if (is_catchpoint_event(dbgee, &cp_event_index,
                                                event)) {
                                breakpoint_handled = true;
                                if (handle_catchpoint_event(dbgee,
                                                            cp_event_index) !=
                                    EXIT_SUCCESS) {
                                        return EXIT_FAILURE;
                                }
                        } else {
                                printf(COLOR_MAGENTA
                                       "Ignoring event %lx.\n" COLOR_RESET,
                                       event);
                        }
                }

                if (!breakpoint_handled && dbgee->state != SINGLE_STEPPING) {
                        printf(COLOR_MAGENTA
                               "Ignoring signal %d.\n" COLOR_RESET,
                               sig);
                }
        }

        dbgee->state = STOPPED;
        return EXIT_SUCCESS;
}

static int _step_replaced_instruction(debuggee *dbgee) {
        if (Step(dbgee) != EXIT_SUCCESS) {
                (void)(fprintf(stderr, COLOR_RED
                               "Failed to execute single step.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }
        dbgee->state = STOPPED;

        int wait_status;
        if (waitpid(dbgee->pid, &wait_status, 0) == -1) {
                perror("waitpid");
                return EXIT_FAILURE;
        }

        if (WIFEXITED(wait_status)) {
                printf(COLOR_YELLOW "Debuggee exited with status %d during "
                                    "single step.\n" COLOR_RESET,
                       WEXITSTATUS(wait_status));
                dbgee->state = TERMINATED;
                return EXIT_FAILURE;
        }

        if (WIFSIGNALED(wait_status)) {
                printf(COLOR_YELLOW "Debuggee was killed by signal %d during "
                                    "single step.\n" COLOR_RESET,
                       WTERMSIG(wait_status));
                dbgee->state = TERMINATED;
                return EXIT_FAILURE;
        }

        if (WIFSTOPPED(wait_status)) {
                int sig = WSTOPSIG(wait_status);
                if (sig != SIGTRAP) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Received unexpected signal %d during "
                                       "single step.\n" COLOR_RESET,
                                       sig));
                        return EXIT_FAILURE;
                }
        } else {
                (void)(fprintf(stderr,
                               COLOR_RED "Debuggee did not stop as expected "
                                         "during single step.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static int _get_return_address(debuggee *dbgee, unsigned long *ret_addr_out) {
        struct user_regs_struct regs;
        unsigned long rsp;
        errno = 0;

        if (ptrace(PTRACE_GETREGS, dbgee->pid, NULL, &regs) == -1) {
                perror("ptrace GETREGS");
                return -1;
        }

        rsp = regs.rsp;

        errno = 0;
        unsigned long return_address =
            ptrace(PTRACE_PEEKDATA, dbgee->pid, rsp, NULL);
        if (return_address == (unsigned long)-1 && errno != 0) {
                perror("ptrace PEEKDATA for return address");
                return -1;
        }

        *ret_addr_out = return_address;
        return 0;
}

static bool _get_available_debug_register(debuggee *dbgee, int *bpno,
                                          unsigned long *dr_offset) {
        unsigned long dr0;
        unsigned long dr1;
        unsigned long dr2;
        unsigned long dr3;
        if (_read_debug_register(dbgee->pid, DR0_OFFSET, &dr0) != 0 ||
            _read_debug_register(dbgee->pid, DR1_OFFSET, &dr1) != 0 ||
            _read_debug_register(dbgee->pid, DR2_OFFSET, &dr2) != 0 ||
            _read_debug_register(dbgee->pid, DR3_OFFSET, &dr3) != 0) {
                return EXIT_FAILURE;
        }

        if (dr0 == 0) {
                *bpno = 0;
        } else if (dr1 == 0) {
                *bpno = 1;
        } else if (dr2 == 0) {
                *bpno = 2;
        } else if (dr3 == 0) {
                *bpno = 3;
        } else {
                return false;
        }

        switch (*bpno) {
        case 0:
                *dr_offset = DR0_OFFSET;
                break;
        case 1:
                *dr_offset = DR1_OFFSET;
                break;
        case 2:
                *dr_offset = DR2_OFFSET;
                break;
        case 3:
                *dr_offset = DR3_OFFSET;
                break;
        default:
                return false;
        }

        return true;
}

static int _set_rip(debuggee *dbgee, unsigned long rip) {
        if (!_is_valid_address(dbgee, rip)) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Error: Invalid RIP address 0x%lx. Address is "
                               "not mapped or not executable.\n" COLOR_RESET,
                               rip));
                return EXIT_FAILURE;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, dbgee->pid, NULL, &regs) == -1) {
                perror("ptrace GETREGS");
                return EXIT_FAILURE;
        }

        regs.rip = rip;

        if (ptrace(PTRACE_SETREGS, dbgee->pid, NULL, &regs) == -1) {
                perror("ptrace SETREGS");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static int _read_rip(debuggee *dbgee, unsigned long *rip) {
        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, dbgee->pid, NULL, &regs) == -1) {
                perror("ptrace GETREGS");
                return EXIT_FAILURE;
        }

        *rip = regs.rip;
        return EXIT_SUCCESS;
}

static bool _set_sw_breakpoint(pid_t pid, uint64_t addr,
                               uint64_t *code_at_addr) {
        errno = 0;
        uint64_t int3 = INT3_OPCODE;
        *code_at_addr = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
        if (*code_at_addr == (uint64_t)-1 && errno != 0) {
                perror("Error reading data with PTRACE_PEEKDATA");
                return false;
        }
        uint64_t code_break = (*code_at_addr & ~MAX_BYTE_VALUE) | int3;

        if (ptrace(PTRACE_POKEDATA, pid, addr, code_break) == -1) {
                perror("Error writing data with PTRACE_POKEDATA");
                return false;
        }

        return true;
}

static int _replace_sw_breakpoint(pid_t pid, uint64_t addr, uint64_t old_byte) {
        errno = 0;
        uint64_t code_at_addr = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
        if (code_at_addr == (uint64_t)-1 && errno != 0) {
                perror("Error reading data with PTRACE_PEEKDATA");
                return EXIT_FAILURE;
        }

        uint64_t code_restored = (code_at_addr & ~MAX_BYTE_VALUE) | old_byte;

        if (ptrace(PTRACE_POKEDATA, pid, addr, code_restored) == -1) {
                perror("Error writing data with PTRACE_POKEDATA");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static bool _parse_breakpoint_argument(debuggee *dbgee, const char *arg,
                                       uintptr_t *address_out) {
        if (arg == NULL || address_out == NULL) {
                (void)(fprintf(stderr, COLOR_RED
                               "Invalid arguments to "
                               "parse_breakpoint_argument.\n" COLOR_RESET));
                return false;
        }

        if (arg[0] == '*') {
                unsigned long rip;
                unsigned long base_address;
                char module_name[MODULE_NAME_SIZE] = {0};

                char *endptr;
                uintptr_t offset = strtoull(arg + 1, &endptr, 0);
                if (*endptr != '\0') {
                        (void)(fprintf(
                            stderr,
                            COLOR_RED "Invalid offset format: %s\n" COLOR_RESET,
                            arg + 1));
                        return false;
                }

                if (_read_rip(dbgee, &rip) != 0) {
                        (void)(fprintf(
                            stderr, COLOR_RED
                            "Failed to retrieve current RIP.\n" COLOR_RESET));
                        return false;
                }

                base_address = _get_module_base_address(
                    dbgee->pid, rip, module_name, sizeof(module_name));
                if (base_address == 0) {
                        (void)(fprintf(stderr, COLOR_RED
                                       "Failed to retrieve base address for "
                                       "offset calculation.\n" COLOR_RESET));
                        return false;
                }

                *address_out = base_address + offset;
        } else if (arg[0] == '&') {
                unsigned long func_offset = _get_symbol_offset(dbgee, arg + 1);
                if (func_offset == 0) {
                        (void)(fprintf(
                            stderr, COLOR_RED
                            "Failed to get func symbol offset.\n" COLOR_RESET));
                        return false;
                }

                unsigned long base_address = _get_load_base(dbgee);
                if (base_address == 0) {
                        (void)(fprintf(
                            stderr, COLOR_RED
                            "Failed to get base address.\n" COLOR_RESET));
                        return false;
                }

                *address_out = base_address + func_offset;
        } else {
                char *endptr;

                uintptr_t address = strtoull(arg, &endptr, 0);
                if (*endptr != '\0') {
                        (void)(fprintf(
                            stderr,
                            COLOR_RED
                            "Invalid address format: %s\n" COLOR_RESET,
                            arg));
                        return false;
                }

                *address_out = address;
        }

        if (!_is_valid_address(dbgee, *address_out)) {
                *address_out = 0;
        }

        return true;
}

void Help(void) {
        printf(COLOR_CYAN "Z Anti-Anti-Debugger - Command List:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "================================================="
                             "==============\n" COLOR_RESET);

        printf(COLOR_YELLOW "General Commands:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);
        printf(
            COLOR_GREEN
            "  help                - Display this help message\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  exit                - Exit the debugger\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  clear               - Clear the screen\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  !!                  - Repeat last command\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);

        printf(COLOR_YELLOW "Execution Commands:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);
        printf(
            COLOR_GREEN
            "  run                 - Run the debuggee program\n" COLOR_RESET);
        printf(COLOR_GREEN "  con                 - Continue execution of the "
                           "debuggee\n" COLOR_RESET);
        printf(COLOR_GREEN "  step                - Execute the next "
                           "instruction (single step)\n" COLOR_RESET);
        printf(COLOR_GREEN "  over                - Step over the current "
                           "instruction\n" COLOR_RESET);
        printf(COLOR_GREEN "  out                 - Step out of the current "
                           "function\n" COLOR_RESET);
        printf(COLOR_GREEN "  skip <n>            - Advances instruction "
                           "pointer by <n> instructions\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  jump <addr>         - Execute until <addr>\n" COLOR_RESET);
        printf(COLOR_GREEN "  jump *<offset>      - Execute until base_address "
                           "+ <offset>\n" COLOR_RESET);
        printf(COLOR_GREEN "  jump &<func_name>   - Execute until base_address "
                           "+ <offset>\n" COLOR_RESET);
        printf(COLOR_GREEN "  trace <addr>        - Trace execution starting "
                           "at <addr>\n" COLOR_RESET);
        printf(COLOR_GREEN "  trace *<offset>     - Trace execution starting "
                           "at base_address + <offset>\n" COLOR_RESET);
        printf(COLOR_GREEN "  trace &<func_name>  - Trace execution starting "
                           "at address of function <func_name>\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);

        printf(COLOR_YELLOW "Breakpoint Commands:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  points              - List all breakpoints\n" COLOR_RESET);
        printf(COLOR_GREEN "  break <addr>        - Set a software breakpoint "
                           "at <addr>\n" COLOR_RESET);
        printf(COLOR_GREEN "  break *<offset>     - Set a software breakpoint "
                           "at base_address + <offset>\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  break &<func_name>  - Set a software breakpoint at the "
               "address of function <func_name>\n" COLOR_RESET);
        printf(COLOR_GREEN "  hbreak <addr>       - Set a hardware breakpoint "
                           "at <addr>\n" COLOR_RESET);
        printf(COLOR_GREEN "  hbreak *<offset>    - Set a hardware breakpoint "
                           "at base_address + <offset>\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  hbreak &<func_name> - Set a hardware breakpoint at the "
               "address of function <func_name>\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  watch <addr>        - Set a watchpoint on memory address "
               "<addr> for read/write access\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  watch *<offset>     - Set a watchpoint at base_address + "
               "<offset> for read/write access\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  watch &<var_name>   - Set a watchpoint on global variable "
               "<var_name> for read/write access\n" COLOR_RESET);
        printf(COLOR_GREEN "  catch <sig_num>     - Set a catchpoint for "
                           "signal number <sig_num>\n" COLOR_RESET);
        printf(COLOR_GREEN
               "  catch <event_name>  - Set a catchpoint for process events: "
               "fork, vfork, clone, exec, exit\n" COLOR_RESET);
        printf(COLOR_GREEN "  remove <idx>        - Remove the breakpoint at "
                           "index <idx>\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);

        printf(COLOR_YELLOW "Inspection Commands:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);
        printf(COLOR_GREEN "  regs                - Display CPU registers "
                           "(general-purpose and debug)\n" COLOR_RESET);
        printf(COLOR_GREEN "  dump                - Dump memory at the current "
                           "instruction pointer\n" COLOR_RESET);
        printf(COLOR_GREEN "  dis                 - Disassemble memory at the "
                           "current instruction pointer\n" COLOR_RESET);
        printf(COLOR_GREEN "  vars                - Display global variables "
                           "and their values\n" COLOR_RESET);
        printf(COLOR_GREEN "  funcs               - List function names with "
                           "addresses\n" COLOR_RESET);
        printf(COLOR_MAGENTA "================================================="
                             "==============\n" COLOR_RESET);
}

int Run(debuggee *dbgee) {
        if (dbgee->bp_handler == NULL) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Invalid debuggee or breakpoint handler.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        if (dbgee->has_run) {
                if (dbgee->bp_handler->count > 0) {
                        if (should_remove_breakpoints(dbgee)) {
                                if (_remove_all_breakpoints(dbgee) !=
                                    EXIT_SUCCESS) {
                                        return EXIT_FAILURE;
                                }

                                if (Continue(dbgee) != EXIT_SUCCESS) {
                                        (void)(fprintf(
                                            stderr, COLOR_RED
                                            "Failed to continue "
                                            "execution.\n" COLOR_RESET));
                                        return EXIT_FAILURE;
                                }

                                printf(COLOR_GREEN
                                       "Debuggee is running until "
                                       "termination.\n" COLOR_RESET);
                                return EXIT_SUCCESS;
                        }
                }
        } else {
                dbgee->has_run = true;
        }

        if (Continue(dbgee) != EXIT_SUCCESS) {
                (void)(fprintf(stderr, COLOR_RED
                               "Failed to continue execution.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

int Continue(debuggee *dbgee) {
        if (!dbgee->has_run) {
                (void)(fprintf(stderr,
                               COLOR_RED "Warning: 'run' must be executed "
                                         "before 'continue'.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        if (ptrace(PTRACE_CONT, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace CONT");
                return EXIT_FAILURE;
        }

        dbgee->state = RUNNING;
        return EXIT_SUCCESS;
}

int Step(debuggee *dbgee) {
        if (ptrace(PTRACE_SINGLESTEP, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace SINGLESTEP");
                return EXIT_FAILURE;
        }

        dbgee->state = SINGLE_STEPPING;
        return EXIT_SUCCESS;
}

int StepOver(debuggee *dbgee) {
        unsigned long rip;
        if (_read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to read RIP for StepOver.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        unsigned long final_addr = rip;
        while (_is_call_instruction(dbgee, final_addr)) {

                // Set temporary breakpoint at the instruction after the call
                // instruction. On x86_64 we know that we need to add 5. 1 byte
                // for oppcode and 4 for the relative offset.
                final_addr += NEXT_INSTRUCTION_OFFSET;
        }

        if (final_addr == rip) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Current instruction at 0x%lx is not a call.\n" COLOR_RESET,
                    rip));
                return EXIT_FAILURE;
        }

        if (set_temp_sw_breakpoint(dbgee, final_addr) != EXIT_SUCCESS) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to set temporary breakpoint "
                                         "at 0x%lx.\n" COLOR_RESET,
                               final_addr));
                return EXIT_FAILURE;
        }

        if (ptrace(PTRACE_CONT, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace CONT");
                return EXIT_FAILURE;
        }
        dbgee->state = RUNNING;

        return EXIT_SUCCESS;
}

int StepOut(debuggee *dbgee) {
        unsigned long return_address;

        if (_get_return_address(dbgee, &return_address) != 0) {
                (void)fprintf(stderr,
                              COLOR_RED "Failed to retrieve return address for "
                                        "StepOut.\n" COLOR_RESET);
                return EXIT_FAILURE;
        }

        printf(COLOR_GREEN "Return address found at 0x%lx\n" COLOR_RESET,
               return_address);

        if (set_temp_sw_breakpoint(dbgee, return_address) != EXIT_SUCCESS) {
                (void)fprintf(stderr,
                              COLOR_RED "Failed to set temporary breakpoint at "
                                        "return address 0x%lx.\n" COLOR_RESET,
                              return_address);
                return EXIT_FAILURE;
        }

        if (ptrace(PTRACE_CONT, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace CONT");
                return EXIT_FAILURE;
        }

        dbgee->state = RUNNING;
        return EXIT_SUCCESS;
}

int Skip(debuggee *dbgee, const char *arg) {
        int n = (int)strtol(arg, NULL, DECIMAL_BASE_PARAMETER);

        if (n <= 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Invalid number of instructions to skip: %s\n" COLOR_RESET,
                    arg));
                return EXIT_FAILURE;
        }

        for (int i = 0; i < n; i++) {
                if (_step_and_wait(dbgee) != EXIT_SUCCESS) {
                        (void)(fprintf(stderr, COLOR_RED
                                       "Failed to single step.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }
        }

        return EXIT_SUCCESS;
}

int Jump(debuggee *dbgee, const char *arg) { // NOLINT
        uintptr_t address = 0;
        if (!_parse_breakpoint_argument(dbgee, arg, &address)) {
                return EXIT_FAILURE;
        }

        if (address == 0) {
                (void)(fprintf(stderr,
                               COLOR_RED "Invalid address: %s\n" COLOR_RESET,
                               arg));
                return EXIT_FAILURE;
        }

        if (set_temp_sw_breakpoint(dbgee, address) != EXIT_SUCCESS) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to set temporary breakpoint "
                                         "at 0x%lx.\n" COLOR_RESET,
                               address));
                return EXIT_FAILURE;
        }

        bool jump_complete = false;

        while (!jump_complete) {
                if (ptrace(PTRACE_CONT, dbgee->pid, NULL, NULL) == -1) {
                        perror("ptrace CONT");
                        return EXIT_FAILURE;
                }

                int wait_status;
                if (waitpid(dbgee->pid, &wait_status, 0) == -1) {
                        perror("waitpid");
                        return EXIT_FAILURE;
                }

                if (WIFEXITED(wait_status)) {
                        printf(COLOR_YELLOW "Debuggee exited with status %d "
                                            "during jump.\n" COLOR_RESET,
                               WEXITSTATUS(wait_status));
                        dbgee->state = TERMINATED;
                        return EXIT_FAILURE;
                }

                if (WIFSIGNALED(wait_status)) {
                        printf(COLOR_YELLOW "Debuggee was killed by signal %d "
                                            "during jump.\n" COLOR_RESET,
                               WTERMSIG(wait_status));
                        dbgee->state = TERMINATED;
                        return EXIT_FAILURE;
                }

                if (WIFSTOPPED(wait_status)) {
                        int sig = WSTOPSIG(wait_status);
                        if (sig == SIGTRAP) {
                                size_t bp_index_hit;
                                bool sw_bp_hit = is_software_breakpoint(
                                    dbgee, &bp_index_hit);

                                if (sw_bp_hit) {
                                        unsigned long rip;
                                        if (_read_rip(dbgee, &rip) != 0) {
                                                return EXIT_FAILURE;
                                        }

                                        if (handle_software_breakpoint(
                                                dbgee, bp_index_hit) !=
                                            EXIT_SUCCESS) {
                                                return EXIT_FAILURE;
                                        }

                                        if (rip - 1 == address) {
                                                printf(COLOR_GREEN
                                                       "Jump completed to "
                                                       "address "
                                                       "0x%lx.\n" COLOR_RESET,
                                                       address);
                                                jump_complete = true;
                                        }
                                }
                                // Ignore all other signals
                        }
                }
        }

        return EXIT_SUCCESS;
}

int Trace(debuggee *dbgee, const char *arg) { // NOLINT
        if (Jump(dbgee, arg) != EXIT_SUCCESS) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to jump to %s.\n" COLOR_RESET,
                               arg));
                return EXIT_FAILURE;
        }

        while (true) {
                if (_step_and_wait(dbgee) != EXIT_SUCCESS) {
                        (void)(fprintf(stderr, COLOR_RED
                                       "Failed to single step.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }

                unsigned long rip;
                if (_read_rip(dbgee, &rip) != EXIT_SUCCESS) {
                        (void)(fprintf(stderr, COLOR_RED
                                       "Failed to read RIP.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }

                unsigned char buf[MAX_X86_INSTRUCT_LEN];
                if (_read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                        (void)(fprintf(
                            stderr,
                            COLOR_RED
                            "Failed to read memory at 0x%lx\n" COLOR_RESET,
                            rip));
                        return EXIT_FAILURE;
                }

                csh handle;
                cs_insn *insn;
                size_t count;

                if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                        (void)(fprintf(
                            stderr, COLOR_RED
                            "Failed to initialize Capstone.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }

                cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
                count = cs_disasm(handle, buf, sizeof(buf), rip, 1, &insn);
                if (count > 0) {
                        printf(COLOR_CYAN "0x%016lx: " COLOR_RESET,
                               insn[0].address);
                        printf(COLOR_GREEN "%-10s" COLOR_RESET " %s\n",
                               insn[0].mnemonic, insn[0].op_str);

                        if (strcmp(insn[0].mnemonic, "ret") == 0 ||
                            strcmp(insn[0].mnemonic, "hlt") == 0) {
                                printf(COLOR_YELLOW
                                       "Trace completed at 0x%lx\n" COLOR_RESET,
                                       insn[0].address);
                                cs_free(insn, count);
                                cs_close(&handle);
                                break;
                        }
                        cs_free(insn, count);
                } else {
                        (void)(fprintf(
                            stderr,
                            COLOR_RED
                            "Failed to disassemble at 0x%lx\n" COLOR_RESET,
                            rip));
                        (void)(fprintf(stderr,
                                       COLOR_RED "Raw bytes: " COLOR_RESET));
                        for (size_t i = 0; i < sizeof(buf); ++i) {
                                (void)(fprintf(stderr,
                                               COLOR_RED "%02x " COLOR_RESET,
                                               buf[i]));
                        }
                        (void)(fprintf(stderr, "\n"));
                        cs_close(&handle);
                        return EXIT_FAILURE;
                }

                cs_close(&handle);
        }

        return EXIT_SUCCESS;
}

int Registers(debuggee *dbgee) {
        struct user_regs_struct regs;
        unsigned long dr0;
        unsigned long dr1;
        unsigned long dr2;
        unsigned long dr3;
        unsigned long dr7;

        if (ptrace(PTRACE_GETREGS, dbgee->pid, NULL, &regs) == -1) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Failed to get registers: %s\n" COLOR_RESET,
                               strerror(errno)));
                return EXIT_FAILURE;
        }

        if (_read_debug_register(dbgee->pid, DR0_OFFSET, &dr0) != 0) {
                return EXIT_FAILURE;
        }
        if (_read_debug_register(dbgee->pid, DR1_OFFSET, &dr1) != 0) {
                return EXIT_FAILURE;
        }
        if (_read_debug_register(dbgee->pid, DR2_OFFSET, &dr2) != 0) {
                return EXIT_FAILURE;
        }
        if (_read_debug_register(dbgee->pid, DR3_OFFSET, &dr3) != 0) {
                return EXIT_FAILURE;
        }
        if (_read_debug_register(dbgee->pid, DR7_OFFSET, &dr7) != 0) {
                return EXIT_FAILURE;
        }

        printf(COLOR_CYAN "Register values for PID %d:\n" COLOR_RESET,
               dbgee->pid);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "-------------\n" COLOR_RESET);

        printf(COLOR_YELLOW "General Purpose Registers:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "-------------\n" COLOR_RESET);
        printf("  " COLOR_GREEN "R15: 0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "R14: 0x%016llx\n" COLOR_RESET,
               regs.r15, regs.r14);
        printf("  " COLOR_GREEN "R13: 0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "R12: 0x%016llx\n" COLOR_RESET,
               regs.r13, regs.r12);
        printf("  " COLOR_GREEN "R11: 0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "R10: 0x%016llx\n" COLOR_RESET,
               regs.r11, regs.r10);
        printf("  " COLOR_GREEN "R9:  0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "R8:  0x%016llx\n" COLOR_RESET,
               regs.r9, regs.r8);
        printf("  " COLOR_GREEN "RAX: 0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "RBX: 0x%016llx\n" COLOR_RESET,
               regs.rax, regs.rbx);
        printf("  " COLOR_GREEN "RCX: 0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "RDX: 0x%016llx\n" COLOR_RESET,
               regs.rcx, regs.rdx);
        printf("  " COLOR_GREEN "RSI: 0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "RDI: 0x%016llx\n" COLOR_RESET,
               regs.rsi, regs.rdi);
        printf("  " COLOR_GREEN "RBP: 0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "RSP: 0x%016llx\n" COLOR_RESET,
               regs.rbp, regs.rsp);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "-------------\n" COLOR_RESET);

        printf(COLOR_YELLOW "Instruction Pointer and Flags:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "-------------\n" COLOR_RESET);
        printf("  " COLOR_GREEN "RIP: 0x%016llx" COLOR_RESET "    " COLOR_GREEN
               "EFL: 0x%016llx\n" COLOR_RESET,
               regs.rip, regs.eflags);
        printf("  " COLOR_GREEN "CS:  0x%016llx\n" COLOR_RESET, regs.cs);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "-------------\n" COLOR_RESET);

        printf(COLOR_YELLOW "Debug Registers:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "-------------\n" COLOR_RESET);
        printf("  " COLOR_GREEN "DR0: 0x%016lx" COLOR_RESET "    " COLOR_GREEN
               "DR1: 0x%016lx\n" COLOR_RESET,
               dr0, dr1);
        printf("  " COLOR_GREEN "DR2: 0x%016lx" COLOR_RESET "    " COLOR_GREEN
               "DR3: 0x%016lx\n" COLOR_RESET,
               dr2, dr3);
        printf("  " COLOR_GREEN "DR7: 0x%016lx\n" COLOR_RESET, dr7);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "-------------\n" COLOR_RESET);

        return EXIT_SUCCESS;
}

int SetSoftwareBreakpoint(debuggee *dbgee, const char *arg) {
        uintptr_t address = 0;
        if (!_parse_breakpoint_argument(dbgee, arg, &address)) {
                return EXIT_FAILURE;
        }

        if (address == 0) {
                (void)(fprintf(stderr,
                               COLOR_RED "Invalid address: %s\n" COLOR_RESET,
                               arg));
                return EXIT_FAILURE;
        }

        if (_breakpoint_exists(dbgee, address)) {
                (void)(fprintf(stderr,
                               COLOR_RED "A breakpoint already exists at "
                                         "address 0x%lx\n" COLOR_RESET,
                               address));
                return EXIT_FAILURE;
        }

        uint64_t original_byte;
        if (!_set_sw_breakpoint(dbgee->pid, address, &original_byte)) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to set software breakpoint at 0x%lx.\n" COLOR_RESET,
                    address));
                return EXIT_FAILURE;
        }

        size_t bp_index =
            add_software_breakpoint(dbgee->bp_handler, address, original_byte);
        printf(COLOR_GREEN
               "Software breakpoint set at 0x%lx [Index: %zu]\n" COLOR_RESET,
               address, bp_index);

        return EXIT_SUCCESS;
}

int SetHardwareBreakpoint(debuggee *dbgee, const char *arg) {
        uintptr_t address = 0;
        if (!_parse_breakpoint_argument(dbgee, arg, &address)) {
                return EXIT_FAILURE;
        }

        if (address == 0) {
                (void)(fprintf(stderr,
                               COLOR_RED "Invalid address: %s\n" COLOR_RESET,
                               arg));
                return EXIT_FAILURE;
        }

        if (_breakpoint_exists(dbgee, address)) {
                (void)(fprintf(stderr,
                               COLOR_RED "A breakpoint already exists at "
                                         "address 0x%lx\n" COLOR_RESET,
                               address));
                return EXIT_FAILURE;
        }

        int bpno = 0;
        unsigned long dr_offset = 0;
        if (!_get_available_debug_register(dbgee, &bpno, &dr_offset)) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "No available hardware debug registers.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        if (_set_debug_register(dbgee->pid, dr_offset, address) != 0) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Failed to set DR%d to 0x%lx.\n" COLOR_RESET,
                               bpno, address));
                return EXIT_FAILURE;
        }

        if (_configure_dr7(dbgee->pid, bpno, 0x0, 0x0, true) != 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to configure DR7 for breakpoint %d.\n" COLOR_RESET,
                    bpno));
                return EXIT_FAILURE;
        }

        size_t bp_index = add_hardware_breakpoint(dbgee->bp_handler, address);
        printf(
            COLOR_GREEN
            "Hardware breakpoint set at 0x%lx [Index: %zu, DR%d]\n" COLOR_RESET,
            address, bp_index, bpno);

        return EXIT_SUCCESS;
}

int SetWatchpoint(debuggee *dbgee, const char *arg) {
        uintptr_t address = 0;

        if (!_parse_breakpoint_argument(dbgee, arg, &address)) {
                return EXIT_FAILURE;
        }

        if (address == 0) {
                (void)(fprintf(stderr,
                               COLOR_RED "Invalid address: %s\n" COLOR_RESET,
                               arg));
                return EXIT_FAILURE;
        }

        if (_breakpoint_exists(dbgee, address)) {
                (void)(fprintf(stderr,
                               COLOR_RED "A watchpoint already exists at "
                                         "address 0x%lx\n" COLOR_RESET,
                               address));
                return EXIT_FAILURE;
        }

        int bpno = 0;
        unsigned long dr_offset = 0;
        if (!_get_available_debug_register(dbgee, &bpno, &dr_offset)) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "No available hardware debug registers.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        if (_set_debug_register(dbgee->pid, dr_offset, address) != 0) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Failed to set DR%d to 0x%lx.\n" COLOR_RESET,
                               bpno, address));
                return EXIT_FAILURE;
        }

        if (_configure_dr7(dbgee->pid, bpno, WATCHPOINT_RW_READ_WRITE,
                           WATCHPOINT_LEN_4_BYTES, true) != 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to configure DR7 for watchpoint %d.\n" COLOR_RESET,
                    bpno));
                return EXIT_FAILURE;
        }

        size_t bp_index = add_watchpoint(dbgee->bp_handler, address);
        if (bp_index == (size_t)-1) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to add watchpoint to handler.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        printf(COLOR_GREEN
               "Watchpoint set at 0x%lx [Index: %zu, DR%d]\n" COLOR_RESET,
               address, bp_index, bpno);
        return EXIT_SUCCESS;
}

int SetCatchpoint(debuggee *dbgee, const char *arg) { // NOLINT
        char *endptr;
        int signal_number = (int)(strtol(arg, &endptr, DECIMAL_BASE_PARAMETER));
        if (*endptr == '\0') {
                if (signal_number < 1 || signal_number > NSIG) {
                        (void)(fprintf(
                            stderr,
                            COLOR_RED "Invalid signal number: %s\n" COLOR_RESET,
                            arg));
                        return EXIT_FAILURE;
                }

                for (size_t i = 0; i < dbgee->bp_handler->count; ++i) {
                        breakpoint *bp = &dbgee->bp_handler->breakpoints[i];
                        if (bp->bp_t == CATCHPOINT_SIGNAL &&
                            bp->data.cp_signal.signal == signal_number) {
                                (void)(fprintf(stderr,
                                               COLOR_RED
                                               "A catchpoint for signal %d "
                                               "already exists.\n" COLOR_RESET,
                                               signal_number));
                                return EXIT_FAILURE;
                        }
                }

                size_t bp_index =
                    add_catchpoint_signal(dbgee->bp_handler, signal_number);
                if (bp_index == (size_t)-1) {
                        (void)(fprintf(stderr,
                                       COLOR_RED "Failed to add catchpoint for "
                                                 "signal %d.\n" COLOR_RESET,
                                       signal_number));
                        return EXIT_FAILURE;
                }

                printf(
                    COLOR_GREEN
                    "Catchpoint set for signal %d [Index: %zu]\n" COLOR_RESET,
                    signal_number, bp_index);
                return EXIT_SUCCESS;
        }

        if (strcmp(arg, "fork") == 0 || strcmp(arg, "vfork") == 0 ||
            strcmp(arg, "clone") == 0 || strcmp(arg, "exec") == 0 ||
            strcmp(arg, "exit") == 0) {

                size_t bp_index = add_catchpoint_event(dbgee->bp_handler, arg);
                if (bp_index == (size_t)-1) {
                        (void)(fprintf(stderr,
                                       COLOR_RED "Failed to add catchpoint for "
                                                 "event '%s'.\n" COLOR_RESET,
                                       arg));
                        return EXIT_FAILURE;
                }

                printf(
                    COLOR_GREEN
                    "Catchpoint set for event '%s' [Index: %zu]\n" COLOR_RESET,
                    arg, bp_index);
                return EXIT_SUCCESS;
        }

        (void)(fprintf(
            stderr, COLOR_RED "Invalid catchpoint argument: %s\n" COLOR_RESET,
            arg));
        (void)(fprintf(
            stderr, COLOR_RED
            "Usage: catch <signal_num> | <event_name>\n" COLOR_RESET));
        return EXIT_FAILURE;
}

int RemoveBreakpoint(debuggee *dbgee, const char *arg) { // NOLINT
        size_t index = strtoull(arg, NULL, DECIMAL_BASE_PARAMETER);
        if (index >= dbgee->bp_handler->count) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Invalid breakpoint index: %zu\n" COLOR_RESET,
                               index));
                return EXIT_FAILURE;
        }

        breakpoint *bp = &dbgee->bp_handler->breakpoints[index];

        switch (bp->bp_t) {
        case SOFTWARE_BP: {
                if (_replace_sw_breakpoint(dbgee->pid, bp->data.sw_bp.address,
                                           bp->data.sw_bp.original_byte) !=
                    EXIT_SUCCESS) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Failed to remove software breakpoint "
                                       "at 0x%lx\n" COLOR_RESET,
                                       bp->data.sw_bp.address));
                        return EXIT_FAILURE;
                }
                printf("Software breakpoint removed at 0x%lx [Index: %zu]\n",
                       bp->data.sw_bp.address, index);
                break;
        }
        case WATCHPOINT:
        case HARDWARE_BP: {
                unsigned long dr0;
                unsigned long dr1;
                unsigned long dr2;
                unsigned long dr3;
                unsigned long dr7;

                if (_read_debug_register(dbgee->pid, DR0_OFFSET, &dr0) !=
                        EXIT_SUCCESS ||
                    _read_debug_register(dbgee->pid, DR1_OFFSET, &dr1) !=
                        EXIT_SUCCESS ||
                    _read_debug_register(dbgee->pid, DR2_OFFSET, &dr2) !=
                        EXIT_SUCCESS ||
                    _read_debug_register(dbgee->pid, DR3_OFFSET, &dr3) !=
                        EXIT_SUCCESS ||
                    _read_debug_register(dbgee->pid, DR7_OFFSET, &dr7) !=
                        EXIT_SUCCESS) {
                        (void)(fprintf(
                            stderr, COLOR_RED
                            "Failed to read debug registers.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }

                int dr_index = -1;
                if (dr0 == bp->data.hw_bp.address) {
                        dr_index = 0;
                } else if (dr1 == bp->data.hw_bp.address) {
                        dr_index = 1;
                } else if (dr2 == bp->data.hw_bp.address) {
                        dr_index = 2;
                } else if (dr3 == bp->data.hw_bp.address) {
                        dr_index = 3;
                } else {
                        (void)(fprintf(stderr, COLOR_RED
                                       "Hardware breakpoint address not found "
                                       "in DR0-DR3.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }

                unsigned long dr_offset;
                switch (dr_index) {
                case 0:
                        dr_offset = DR0_OFFSET;
                        break;
                case 1:
                        dr_offset = DR1_OFFSET;
                        break;
                case 2:
                        dr_offset = DR2_OFFSET;
                        break;
                case 3:
                        dr_offset = DR3_OFFSET;
                        break;
                default:
                        (void)(fprintf(
                            stderr, COLOR_RED
                            "Invalid breakpoint number.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }

                if (_set_debug_register(dbgee->pid, dr_offset, 0) !=
                    EXIT_SUCCESS) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Failed to clear DR%d.\n" COLOR_RESET,
                                       dr_index));
                        return EXIT_FAILURE;
                }

                if (_configure_dr7(dbgee->pid, dr_index, 0, 0, false) !=
                    EXIT_SUCCESS) {
                        (void)(fprintf(stderr,
                                       COLOR_RED "Failed to update DR7 after "
                                                 "clearing DR%d.\n" COLOR_RESET,
                                       dr_index));
                        return EXIT_FAILURE;
                }

                printf(COLOR_GREEN "Hardware breakpoint removed at 0x%lx "
                                   "[Index: %zu, DR%d]\n" COLOR_RESET,
                       bp->data.hw_bp.address, index, dr_index);
                break;
        }
        case CATCHPOINT_SIGNAL:
        case CATCHPOINT_EVENT_FORK:
        case CATCHPOINT_EVENT_VFORK:
        case CATCHPOINT_EVENT_CLONE:
        case CATCHPOINT_EVENT_EXEC:
        case CATCHPOINT_EVENT_EXIT:
                printf(COLOR_GREEN
                       "Catchpoint removed [Index: %zu]\n" COLOR_RESET,
                       index);
                break;
        default:
                (void)(fprintf(stderr, COLOR_RED
                               "Unknown breakpoint type.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        if (remove_breakpoint(dbgee->bp_handler, index) != EXIT_SUCCESS) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to remove catchpoint from handler.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

void ListBreakpoints(debuggee *dbgee) { list_breakpoints(dbgee->bp_handler); }

int Dump(debuggee *dbgee) { // NOLINT
        unsigned long rip;
        unsigned char buf[DUMP_SIZE];
        unsigned long base_address;
        char module_name[MODULE_NAME_SIZE] = {0};
        size_t dump_length = DUMP_SIZE;

        if (_read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED "Failed to retrieve current RIP.\n" COLOR_RESET));
                return -1;
        }

        base_address = _get_module_base_address(dbgee->pid, rip, module_name,
                                                sizeof(module_name));
        if (base_address == 0) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to retrieve base address.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        if (_read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Failed to read memory at 0x%lx\n" COLOR_RESET,
                               rip));
                return EXIT_FAILURE;
        }

        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                (void)(fprintf(stderr, COLOR_RED
                               "Failed to initialize Capstone.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

        count = cs_disasm(handle, buf, sizeof(buf), rip, 0, &insn);
        if (count > 0) {
                for (size_t i = 0; i < count; i++) {
                        size_t insn_length = insn[i].size;
                        if (strcmp(insn[i].mnemonic, "ret") == 0) {
                                dump_length =
                                    insn[i].address - rip + insn_length;
                                break;
                        }
                }
                cs_free(insn, count);
        } else {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to disassemble memory at 0x%lx.\n" COLOR_RESET,
                    rip));
                cs_close(&handle);
                return EXIT_FAILURE;
        }

        cs_close(&handle);

        printf(COLOR_CYAN "Memory dump in module '%s' at RIP: 0x%016lx "
                          "(Offset: 0x%lx)\n" COLOR_RESET,
               module_name, rip, rip - base_address);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);
        printf(COLOR_YELLOW "Offset              Hexadecimal                   "
                            "          ASCII\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);

        for (size_t i = 0; i < dump_length; i += WORD_LENGTH) {
                unsigned long current_address = rip + i;
                unsigned long offset = current_address - base_address;

                printf(COLOR_GREEN "0x%016lx (0x%lx): " COLOR_RESET,
                       current_address, offset);

                for (size_t j = 0; j < WORD_LENGTH; ++j) {
                        if (i + j < dump_length) {
                                printf(COLOR_YELLOW "%02x " COLOR_RESET,
                                       buf[i + j]);
                        } else {
                                printf("   ");
                        }
                }

                printf("  ");

                for (size_t j = 0; j < WORD_LENGTH; ++j) {
                        if (i + j < dump_length) {
                                unsigned char c = buf[i + j];
                                printf(COLOR_WHITE "%c" COLOR_RESET,
                                       (c >= ASCII_PRINTABLE_MIN &&
                                        c <= ASCII_PRINTABLE_MAX)
                                           ? c
                                           : '.');
                        }
                }

                printf("\n");

                if (i + WORD_LENGTH >= dump_length) {
                        break;
                }
        }

        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "--------------\n" COLOR_RESET);

        return EXIT_SUCCESS;
}

int Disassemble(debuggee *dbgee) {
        unsigned long rip;
        unsigned char buf[DUMP_SIZE];
        csh handle;
        cs_insn *insn;
        size_t count;
        unsigned long base_address;
        char module_name[MODULE_NAME_SIZE] = {0};

        if (_read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED "Failed to retrieve current RIP.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        base_address = _get_module_base_address(dbgee->pid, rip, module_name,
                                                sizeof(module_name));
        if (base_address == 0) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to retrieve base address.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        if (_read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                (void)(fprintf(stderr,
                               COLOR_RED
                               "Failed to read memory at 0x%lx\n" COLOR_RESET,
                               rip));
                return EXIT_FAILURE;
        }

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                (void)(fprintf(stderr, COLOR_RED
                               "Failed to initialize Capstone\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

        unsigned long offset = rip - base_address;
        printf(COLOR_CYAN
               "Disassembling memory in module '%s' at RIP: " COLOR_GREEN
               "0x%016lx" COLOR_CYAN " (Offset: " COLOR_YELLOW
               "0x%lx" COLOR_CYAN ")\n" COLOR_RESET,
               module_name, rip, offset);

        count = cs_disasm(handle, buf, sizeof(buf), rip, 0, &insn);
        if (count > 0) {
                printf(COLOR_MAGENTA "-----------------------------------------"
                                     "----------------------\n" COLOR_RESET);
                for (size_t i = 0; i < count; i++) {
                        unsigned long insn_offset =
                            insn[i].address - base_address;
                        printf(COLOR_GREEN "0x%016lx" COLOR_RESET
                                           " (" COLOR_YELLOW "0x%lx" COLOR_RESET
                                           "): " COLOR_BLUE "%-10s" COLOR_RESET
                                           "\t%s\n",
                               insn[i].address, insn_offset, insn[i].mnemonic,
                               insn[i].op_str);

                        if (strcmp(insn[i].mnemonic, "ret") == 0) {
                                break;
                        }
                }
                printf(COLOR_MAGENTA "-----------------------------------------"
                                     "----------------------\n" COLOR_RESET);
                cs_free(insn, count);
        } else {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to disassemble given code!\n" COLOR_RESET));
        }

        cs_close(&handle);

        return EXIT_SUCCESS;
}

int DisplayGlobalVariables(debuggee *dbgee) {
        elf_symtab symtab_struct;
        if (!read_elf_symtab(dbgee->name, &symtab_struct)) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to read ELF symbol tables.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        printf(COLOR_CYAN "Global Variables with Values:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "----------------------\n" COLOR_RESET);
        printf(COLOR_YELLOW "%-40s %-18s %-10s %-20s\n" COLOR_RESET, "Name",
               "Address", "Size", "Value");
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "----------------------\n" COLOR_RESET);

        unsigned long base_address = _get_load_base(dbgee);
        if (base_address == 0) {
                (void)(fprintf(stderr, COLOR_RED
                               "Failed to get base address.\n" COLOR_RESET));
                for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                        free(symtab_struct.entries[i].symtab);
                        free(symtab_struct.entries[i].strtab);
                }
                free(symtab_struct.entries);
                return EXIT_FAILURE;
        }

        for (size_t entry_idx = 0; entry_idx < symtab_struct.num_entries;
             entry_idx++) {
                elf_symtab_entry *entry = &symtab_struct.entries[entry_idx];
                for (size_t j = 0; j < entry->num_symbols; j++) {
                        Elf64_Sym sym = entry->symtab[j];
                        if ((ELF64_ST_TYPE(sym.st_info) != STT_OBJECT) ||
                            (ELF64_ST_BIND(sym.st_info) != STB_GLOBAL) ||
                            (sym.st_shndx == SHN_UNDEF)) {
                                continue;
                        }

                        const char *sym_name = entry->strtab + sym.st_name;
                        if (sym_name == NULL || strlen(sym_name) == 0) {
                                continue;
                        }

                        unsigned long abs_address = base_address + sym.st_value;

                        unsigned long value;
                        errno = 0;
                        value = ptrace(PTRACE_PEEKDATA, dbgee->pid,
                                       (uintptr_t)abs_address, NULL);
                        if (value == (unsigned long)-1 && errno != 0) {
                                perror("ptrace PEEKDATA");
                                continue;
                        }

                        printf(COLOR_YELLOW "%-40s " COLOR_GREEN
                                            "0x%016lx" COLOR_RESET " ",
                               sym_name, abs_address);
                        printf("%-10lu ", sym.st_size);
                        printf(COLOR_GREEN "0x%016lx" COLOR_RESET "\n", value);
                }
        }

        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "----------------------\n" COLOR_RESET);

        for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                free(symtab_struct.entries[i].symtab);
                free(symtab_struct.entries[i].strtab);
        }
        free(symtab_struct.entries);

        return EXIT_SUCCESS;
}

int DisplayFunctionNames(debuggee *dbgee) { // NOLINT
        if (dbgee == NULL || dbgee->name == NULL) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Invalid debuggee or debuggee name.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        elf_symtab symtab_struct;
        if (!read_elf_symtab(dbgee->name, &symtab_struct)) {
                (void)(fprintf(
                    stderr, COLOR_RED
                    "Failed to read ELF symbol tables.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        unsigned long base_address = _get_load_base(dbgee);
        if (base_address == 0) {
                (void)(fprintf(stderr, COLOR_RED
                               "Failed to get base address.\n" COLOR_RESET));
                for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                        free(symtab_struct.entries[i].symtab);
                        free(symtab_struct.entries[i].strtab);
                }
                free(symtab_struct.entries);
                return EXIT_FAILURE;
        }

        printf(COLOR_CYAN "Function Names with Addresses:\n" COLOR_RESET);
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "----------------------\n" COLOR_RESET);
        printf(COLOR_YELLOW "%-40s %-18s %-10s\n" COLOR_RESET, "Name",
               "Address", "Size");
        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "----------------------\n" COLOR_RESET);

        const char *warning_keywords[] = {"time", "timing", "date", "clock",
                                          "rdtsc"};
        size_t num_keywords =
            sizeof(warning_keywords) / sizeof(warning_keywords[0]);

        for (size_t entry_idx = 0; entry_idx < symtab_struct.num_entries;
             entry_idx++) {
                elf_symtab_entry *entry = &symtab_struct.entries[entry_idx];
                for (size_t j = 0; j < entry->num_symbols; j++) {
                        Elf64_Sym sym = entry->symtab[j];

                        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) {
                                continue;
                        }

                        const char *sym_name = entry->strtab + sym.st_name;
                        if (sym_name == NULL || strlen(sym_name) == 0) {
                                continue;
                        }

                        unsigned long abs_address = base_address + sym.st_value;

                        bool should_warn = false;
                        for (size_t k = 0; k < num_keywords; k++) {
                                if (strstr(sym_name, warning_keywords[k])) {
                                        should_warn = true;
                                        break;
                                }
                        }

                        if ((sym.st_size > 0) ||
                            (should_warn && !strstr(sym_name, "@"))) {
                                printf(COLOR_YELLOW "%-40s " COLOR_GREEN
                                                    "0x%016lx" COLOR_RESET
                                                    " %-10lu",
                                       sym_name, abs_address, sym.st_size);

                                if (should_warn) {
                                        printf(" " COLOR_RED
                                               "[WARNING: Time related "
                                               "function]" COLOR_RESET "\n");
                                } else {
                                        printf("\n");
                                }
                        }
                }
        }

        printf(COLOR_MAGENTA "-------------------------------------------------"
                             "----------------------\n" COLOR_RESET);

        for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                free(symtab_struct.entries[i].symtab);
                free(symtab_struct.entries[i].strtab);
        }
        free(symtab_struct.entries);

        return EXIT_SUCCESS;
}

unsigned long get_entry_absolute_address(debuggee *dbgee) {
        int fd = open(dbgee->name, O_RDONLY);
        if (fd < 0) {
                perror("open");
                return 0;
        }

        Elf64_Ehdr ehdr;
        ssize_t bytes_read = read(fd, &ehdr, sizeof(ehdr));
        if (bytes_read != sizeof(ehdr)) {
                perror("read");
                close(fd);
                return 0;
        }
        close(fd);

        unsigned long entry_point = ehdr.e_entry;

        if (ehdr.e_type == ET_DYN) {
                unsigned long base_address = _get_load_base(dbgee);
                if (base_address == 0) {
                        (void)(fprintf(stderr, COLOR_RED
                                       "Failed to get base address for PIE "
                                       "binary.\n" COLOR_RESET));
                        return 0;
                }
                entry_point += base_address;
        }

        printf(COLOR_GREEN "Program entry point: 0x%lx\n" COLOR_RESET,
               entry_point);
        return entry_point;
}

int set_temp_sw_breakpoint(debuggee *dbgee, uint64_t addr) {
        uint64_t original_byte;
        if (!_set_sw_breakpoint(dbgee->pid, addr, &original_byte)) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to set temporary breakpoint "
                                         "at 0x%lx.\n" COLOR_RESET,
                               addr));
                return EXIT_FAILURE;
        }

        size_t bp_index =
            add_software_breakpoint(dbgee->bp_handler, addr, original_byte);
        if (bp_index == (size_t)-1) {
                (void)(fprintf(stderr,
                               COLOR_RED "Failed to add temporary breakpoint "
                                         "to handler.\n" COLOR_RESET));
                return EXIT_FAILURE;
        }

        dbgee->bp_handler->breakpoints[bp_index].temporary = true;

        return EXIT_SUCCESS;
}

bool is_software_breakpoint(debuggee *dbgee, size_t *bp_index_out) {
        unsigned long rip;
        if (_read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED "Failed to retrieve current RIP.\n" COLOR_RESET));
                return false;
        }

        for (size_t i = 0; i < dbgee->bp_handler->count; ++i) {
                breakpoint *bp = &dbgee->bp_handler->breakpoints[i];
                if (bp->bp_t == SOFTWARE_BP &&
                    bp->data.sw_bp.address == (rip - 1)) {
                        if (bp_index_out) {
                                *bp_index_out = i;
                        }
                        return true;
                }
        }
        return false;
}

bool is_hardware_breakpoint(debuggee *dbgee, size_t *bp_index_out) {
        unsigned long rip;
        if (_read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED "Failed to retrieve current RIP.\n" COLOR_RESET));
                return false;
        }

        for (size_t i = 0; i < dbgee->bp_handler->count; ++i) {
                breakpoint *bp = &dbgee->bp_handler->breakpoints[i];
                if (bp->bp_t == HARDWARE_BP && bp->data.hw_bp.address == rip) {
                        if (bp_index_out) {
                                *bp_index_out = i;
                        }
                        return true;
                }
        }
        return false;
}

bool is_catchpoint_signal(debuggee *dbgee, size_t *bp_index_out,
                          int signal_number) {
        for (size_t i = 0; i < dbgee->bp_handler->count; ++i) {
                breakpoint *bp = &dbgee->bp_handler->breakpoints[i];
                if (bp->bp_t == CATCHPOINT_SIGNAL &&
                    bp->data.cp_signal.signal == signal_number) {
                        if (bp_index_out) {
                                *bp_index_out = i;
                        }
                        return true;
                }
        }
        return false;
}

bool is_catchpoint_event(debuggee *dbgee, size_t *bp_index_out,
                         unsigned long event_code) {
        for (size_t i = 0; i < dbgee->bp_handler->count; ++i) {
                breakpoint *bp = &dbgee->bp_handler->breakpoints[i];
                if ((bp->bp_t == CATCHPOINT_EVENT_FORK &&
                     strcmp(bp->data.cp_event.event_name, "fork") == 0 &&
                     event_code == PTRACE_EVENT_FORK) ||
                    (bp->bp_t == CATCHPOINT_EVENT_VFORK &&
                     strcmp(bp->data.cp_event.event_name, "vfork") == 0 &&
                     event_code == PTRACE_EVENT_VFORK) ||
                    (bp->bp_t == CATCHPOINT_EVENT_CLONE &&
                     strcmp(bp->data.cp_event.event_name, "clone") == 0 &&
                     event_code == PTRACE_EVENT_CLONE) ||
                    (bp->bp_t == CATCHPOINT_EVENT_EXEC &&
                     strcmp(bp->data.cp_event.event_name, "exec") == 0 &&
                     event_code == PTRACE_EVENT_EXEC) ||
                    (bp->bp_t == CATCHPOINT_EVENT_EXIT &&
                     strcmp(bp->data.cp_event.event_name, "exit") == 0 &&
                     event_code == PTRACE_EVENT_EXIT)) {
                        if (bp_index_out != NULL) {
                                *bp_index_out = i;
                        }
                        return true;
                }
        }
        return false;
}

bool is_watchpoint(debuggee *dbgee, size_t *bp_index_out) {
        unsigned long dr6;

        if (_read_debug_register(dbgee->pid, DR6_OFFSET, &dr6) != 0) {
                perror("Failed to read DR6");
                return false;
        }

        if ((dr6 & LOWER_FOUR_BYTES_MASK) == 0) {
                return false;
        }

        unsigned long dr0;
        unsigned long dr1;
        unsigned long dr2;
        unsigned long dr3;
        if (_read_debug_register(dbgee->pid, DR0_OFFSET, &dr0) != 0 ||
            _read_debug_register(dbgee->pid, DR1_OFFSET, &dr1) != 0 ||
            _read_debug_register(dbgee->pid, DR2_OFFSET, &dr2) != 0 ||
            _read_debug_register(dbgee->pid, DR3_OFFSET, &dr3) != 0) {
                return false;
        }

        for (size_t i = 0; i < dbgee->bp_handler->count; i++) {
                breakpoint *bp = &dbgee->bp_handler->breakpoints[i];
                if (bp->bp_t == WATCHPOINT) {
                        unsigned long wp_addr = bp->data.wp.address;
                        int dr_index = -1;

                        if (dr0 == wp_addr) {
                                dr_index = 0;
                        } else if (dr1 == wp_addr) {
                                dr_index = 1;
                        } else if (dr2 == wp_addr) {
                                dr_index = 2;
                        } else if (dr3 == wp_addr) {
                                dr_index = 3;
                        }

                        if (dr_index != -1 && (dr6 & (1UL << dr_index))) {
                                if (bp_index_out) {
                                        *bp_index_out = i;
                                }
                                return true;
                        }
                }
        }
        return false;
}

int handle_software_breakpoint(debuggee *dbgee, size_t bp_index) {
        breakpoint *bp = &dbgee->bp_handler->breakpoints[bp_index];
        unsigned long address = bp->data.sw_bp.address;
        unsigned char original_byte = bp->data.sw_bp.original_byte;

        if (_set_rip(dbgee, address) != 0) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to set current RIP to address 0x%lx.\n" COLOR_RESET,
                    address));
                return EXIT_FAILURE;
        }

        if (_replace_sw_breakpoint(dbgee->pid, address, original_byte) !=
            EXIT_SUCCESS) {
                (void)(fprintf(
                    stderr,
                    COLOR_RED
                    "Failed to remove software breakpoint while handling "
                    "software breakpoint at 0x%lx\n" COLOR_RESET,
                    address));
                return EXIT_FAILURE;
        }

        if (bp->temporary) {
                if (remove_breakpoint(dbgee->bp_handler, bp_index) != 0) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Failed to remove temporary breakpoint "
                                       "at 0x%lx.\n" COLOR_RESET,
                                       address));
                        return EXIT_FAILURE;
                }
        } else {
                if (_step_replaced_instruction(dbgee) != EXIT_SUCCESS) {
                        (void)(fprintf(stderr, COLOR_RED
                                       "Failed to single step.\n" COLOR_RESET));
                        return EXIT_FAILURE;
                }

                uint64_t original_data;
                if (!_set_sw_breakpoint(dbgee->pid, address, &original_data)) {
                        (void)(fprintf(stderr,
                                       COLOR_RED
                                       "Failed to re-insert software "
                                       "breakpoint while handling software "
                                       "breakpoint at 0x%lx\n" COLOR_RESET,
                                       address));
                        return EXIT_FAILURE;
                }
        }

        printf(COLOR_MAGENTA "Software breakpoint hit '%lx'.\n" COLOR_RESET,
               address);

        return EXIT_SUCCESS;
}

int handle_hardware_breakpoint(debuggee *dbgee, size_t bp_index) {
        breakpoint *bp = &dbgee->bp_handler->breakpoints[bp_index];
        unsigned long address = bp->data.hw_bp.address;

        printf(COLOR_MAGENTA "Hardware breakpoint hit '%lx'.\n" COLOR_RESET,
               address);

        return EXIT_SUCCESS;
}

int handle_catchpoint_signal(debuggee *dbgee, size_t bp_index) {
        breakpoint *bp = &dbgee->bp_handler->breakpoints[bp_index];
        int signal_number = bp->data.cp_signal.signal;

        printf(COLOR_MAGENTA "Catchpoint '%zu' caught signal %d.\n" COLOR_RESET,
               bp_index, signal_number);

        return EXIT_SUCCESS;
}

int handle_catchpoint_event(debuggee *dbgee, size_t bp_index) {
        breakpoint *bp = &dbgee->bp_handler->breakpoints[bp_index];
        const char *event_name = bp->data.cp_event.event_name;

        printf(COLOR_MAGENTA
               "Event catchpoint for '%s' triggered.\n" COLOR_RESET,
               event_name);

        return EXIT_SUCCESS;
}

int handle_watchpoint(debuggee *dbgee, size_t bp_index) {
        breakpoint *bp = &dbgee->bp_handler->breakpoints[bp_index];
        unsigned long address = bp->data.hw_bp.address;

        printf(COLOR_MAGENTA "Watchpoint hit '%lx'.\n" COLOR_RESET, address);

        return EXIT_SUCCESS;
}
