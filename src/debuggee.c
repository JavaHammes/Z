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

#include "debuggee.h"

#define DR0_OFFSET offsetof(struct user, u_debugreg[0])
#define DR1_OFFSET offsetof(struct user, u_debugreg[1])
#define DR2_OFFSET offsetof(struct user, u_debugreg[2])
#define DR3_OFFSET offsetof(struct user, u_debugreg[3])
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
        printf("There are %zu breakpoints set. Do you want to "
               "remove all breakpoints and run until termination? (y/N): ",
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

void Help(void) {
        printf("Z Anti-Anti-Debugger - Command List:\n");
        printf("==============================================================="
               "\n");
        printf("General Commands:\n");
        printf("---------------------------------------------------------------"
               "\n");
        printf("  help            - Display this help message\n");
        printf("  exit            - Exit the debugger\n");
        printf("  clear           - Clear the screen\n");
        printf("---------------------------------------------------------------"
               "\n");

        printf("Execution Commands:\n");
        printf("---------------------------------------------------------------"
               "\n");
        printf("  run                 - Run the debuggee program\n");
        printf("  con                 - Continue execution of the debuggee\n");
        printf("  step                - Execute the next instruction (single "
               "step)\n");
        printf("  over                - Step over the current instruction\n");
        printf("  out                 - Step out of the current function\n");
        printf("---------------------------------------------------------------"
               "\n");

        printf("Breakpoint Commands:\n");
        printf("---------------------------------------------------------------"
               "\n");
        printf("  points              - List all breakpoints\n");
        printf("  break <addr>        - Set a software breakpoint at <addr>\n");
        printf("  hbreak <addr>       - Set a hardware breakpoint at <addr>\n");
        printf("  break *<offset>     - Set a software breakpoint at "
               "base_address + <offset>\n");
        printf("  hbreak *<offset>    - Set a hardware breakpoint at "
               "base_address + <offset>\n");
        printf("  break &<func_name>  - Set a software breakpoint at the "
               "address of function <func_name>\n");
        printf("  hbreak &<func_name> - Set a hardware breakpoint at the "
               "address of function <func_name>\n");
        printf(
            "  remove <idx>        - Remove the breakpoint at index <idx>\n");
        printf("---------------------------------------------------------------"
               "\n");

        printf("Inspection Commands:\n");
        printf("---------------------------------------------------------------"
               "\n");
        printf("  regs                - Display CPU registers (general-purpose "
               "and "
               "debug)\n");
        printf("  dump                - Dump memory at the current instruction "
               "pointer\n");
        printf("  dis                 - Disassemble memory at the current "
               "instruction pointer\n");
        printf("==============================================================="
               "\n");
}

int Run(debuggee *dbgee) {
        if (dbgee->bp_handler == NULL) {
                (void)(fprintf(stderr,
                               "Invalid debuggee or breakpoint handler.\n"));
                return EXIT_FAILURE;
        }

        if (dbgee->has_run) {
                if (dbgee->bp_handler->count > 0) {
                        if (should_remove_breakpoints(dbgee)) {
                                if (remove_all_breakpoints(dbgee) !=
                                    EXIT_SUCCESS) {
                                        return EXIT_FAILURE;
                                }

                                if (Continue(dbgee) != EXIT_SUCCESS) {
                                        (void)(fprintf(
                                            stderr,
                                            "Failed to continue execution.\n"));
                                        return EXIT_FAILURE;
                                }

                                printf(
                                    "Debuggee is running until termination.\n");
                                return EXIT_SUCCESS;
                        }
                }
        } else {
                dbgee->has_run = true;
        }

        if (Continue(dbgee) != EXIT_SUCCESS) {
                (void)(fprintf(stderr, "Failed to continue execution.\n"));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

int Continue(debuggee *dbgee) {
        if (!dbgee->has_run) {
                (void)(fprintf(
                    stderr,
                    "Warning: 'run' must be executed before 'continue'.\n"));
                return EXIT_FAILURE;
        }

        if (ptrace(PTRACE_CONT, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace CONT");
                return EXIT_FAILURE;
        }

        dbgee->state = RUNNING;
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
                (void)(fprintf(stderr, "Failed to get registers: %s\n",
                               strerror(errno)));
                return EXIT_FAILURE;
        }

        if (read_debug_register(dbgee->pid, DR0_OFFSET, &dr0) != 0) {
                return EXIT_FAILURE;
        }

        if (read_debug_register(dbgee->pid, DR1_OFFSET, &dr1) != 0) {
                return EXIT_FAILURE;
        }

        if (read_debug_register(dbgee->pid, DR2_OFFSET, &dr2) != 0) {
                return EXIT_FAILURE;
        }

        if (read_debug_register(dbgee->pid, DR3_OFFSET, &dr3) != 0) {
                return EXIT_FAILURE;
        }

        if (read_debug_register(dbgee->pid, DR7_OFFSET, &dr7) != 0) {
                return EXIT_FAILURE;
        }

        printf("Register values for PID %d:\n", dbgee->pid);
        printf("---------------------------------------------------------------"
               "----------------------\n");
        printf("General Purpose Registers:\n");
        printf("---------------------------------------------------------------"
               "----------------------\n");
        printf("  R15: 0x%016llx    R14: 0x%016llx\n", regs.r15, regs.r14);
        printf("  R13: 0x%016llx    R12: 0x%016llx\n", regs.r13, regs.r12);
        printf("  R11: 0x%016llx    R10: 0x%016llx\n", regs.r11, regs.r10);
        printf("  R9:  0x%016llx    R8:  0x%016llx\n", regs.r9, regs.r8);
        printf("  RAX: 0x%016llx    RBX: 0x%016llx\n", regs.rax, regs.rbx);
        printf("  RCX: 0x%016llx    RDX: 0x%016llx\n", regs.rcx, regs.rdx);
        printf("  RSI: 0x%016llx    RDI: 0x%016llx\n", regs.rsi, regs.rdi);
        printf("  RBP: 0x%016llx    RSP: 0x%016llx\n", regs.rbp, regs.rsp);
        printf("---------------------------------------------------------------"
               "----------------------\n");
        printf("Instruction Pointer and Flags:\n");
        printf("---------------------------------------------------------------"
               "----------------------\n");
        printf("  RIP: 0x%016llx    EFL: 0x%016llx\n", regs.rip, regs.eflags);
        printf("  CS:  0x%016llx\n", regs.cs);
        printf("---------------------------------------------------------------"
               "----------------------\n");
        printf("Debug Registers:\n");
        printf("---------------------------------------------------------------"
               "----------------------\n");
        printf("  DR0: 0x%016lx    DR1: 0x%016lx\n", dr0, dr1);
        printf("  DR2: 0x%016lx    DR3: 0x%016lx\n", dr2, dr3);
        printf("  DR7: 0x%016lx\n", dr7);
        printf("---------------------------------------------------------------"
               "----------------------\n");

        return EXIT_SUCCESS;
}

int SetSoftwareBreakpoint(debuggee *dbgee, const char *arg) {
        uintptr_t address = 0;
        if (!parse_breakpoint_argument(dbgee, arg, &address)) {
                return EXIT_FAILURE;
        }

        if (address == 0) {
                (void)(fprintf(stderr, "Invalid address: %s\n", arg));
                return EXIT_FAILURE;
        }

        if (breakpoint_exists(dbgee, address)) {
                (void)(fprintf(stderr,
                               "A breakpoint already exists at address 0x%lx\n",
                               address));
                return EXIT_FAILURE;
        }

        uint64_t original_byte;
        if (!set_sw_breakpoint(dbgee->pid, address, &original_byte)) {
                (void)(fprintf(stderr,
                               "Failed to set software breakpoint at 0x%lx.\n",
                               address));
                return EXIT_FAILURE;
        }

        size_t bp_index =
            add_software_breakpoint(dbgee->bp_handler, address, original_byte);
        printf("Software breakpoint set at 0x%lx [Index: %zu]\n", address,
               bp_index);

        return EXIT_SUCCESS;
}

int SetHardwareBreakpoint(debuggee *dbgee, const char *arg) {
        uintptr_t address = 0;
        if (!parse_breakpoint_argument(dbgee, arg, &address)) {
                return EXIT_FAILURE;
        }

        if (address == 0) {
                (void)(fprintf(stderr, "Invalid address: %s\n", arg));
                return EXIT_FAILURE;
        }

        if (breakpoint_exists(dbgee, address)) {
                (void)(fprintf(stderr,
                               "A breakpoint already exists at address 0x%lx\n",
                               address));
                return EXIT_FAILURE;
        }

        int bpno = -1;
        unsigned long dr0;
        unsigned long dr1;
        unsigned long dr2;
        unsigned long dr3;
        if (read_debug_register(dbgee->pid, DR0_OFFSET, &dr0) != 0) {
                return EXIT_FAILURE;
        }
        if (read_debug_register(dbgee->pid, DR1_OFFSET, &dr1) != 0) {
                return EXIT_FAILURE;
        }
        if (read_debug_register(dbgee->pid, DR2_OFFSET, &dr2) != 0) {
                return EXIT_FAILURE;
        }
        if (read_debug_register(dbgee->pid, DR3_OFFSET, &dr3) != 0) {
                return EXIT_FAILURE;
        }

        if (dr0 == 0) {
                bpno = 0;
        } else if (dr1 == 0) {
                bpno = 1;
        } else if (dr2 == 0) {
                bpno = 2;
        } else if (dr3 == 0) {
                bpno = 3;
        } else {
                (void)(fprintf(
                    stderr, "No available hardware breakpoint registers.\n"));
                return EXIT_FAILURE;
        }

        unsigned long dr_offset;
        switch (bpno) {
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
                (void)(fprintf(stderr, "Invalid breakpoint number.\n"));
                return EXIT_FAILURE;
        }

        if (set_debug_register(dbgee->pid, dr_offset, address) != 0) {
                (void)(fprintf(stderr, "Failed to set DR%d to 0x%lx.\n", bpno,
                               address));
                return EXIT_FAILURE;
        }

        if (configure_dr7(dbgee->pid, bpno, 0x0, 0x0, true) != 0) {
                (void)(fprintf(stderr,
                               "Failed to configure DR7 for breakpoint %d.\n",
                               bpno));
                return EXIT_FAILURE;
        }

        size_t bp_index = add_hardware_breakpoint(dbgee->bp_handler, address);
        printf("Hardware breakpoint set at 0x%lx [Index: %zu, DR%d]\n", address,
               bp_index, bpno);

        return EXIT_SUCCESS;
}

int RemoveBreakpoint(debuggee *dbgee, const char *arg) {
        size_t index = strtoull(arg, NULL, DECIMAL_BASE_PARAMETER);
        if (index >= dbgee->bp_handler->count) {
                (void)(fprintf(stderr, "Invalid breakpoint index: %zu\n",
                               index));
                return EXIT_FAILURE;
        }

        breakpoint *bp = &dbgee->bp_handler->breakpoints[index];

        if (bp->bp_t == SOFTWARE_BP) {
                if (replace_sw_breakpoint(dbgee->pid, bp->data.sw_bp.address,
                                          bp->data.sw_bp.original_byte) !=
                    EXIT_SUCCESS) {
                        (void)(fprintf(
                            stderr,
                            "Failed to remove software breakpoint at 0x%lx\n",
                            bp->data.sw_bp.address));
                        return EXIT_FAILURE;
                }
                printf("Software breakpoint removed at 0x%lx [Index: %zu]\n",
                       bp->data.sw_bp.address, index);
        } else if (bp->bp_t == HARDWARE_BP) {
                unsigned long dr0;
                unsigned long dr1;
                unsigned long dr2;
                unsigned long dr3;
                unsigned long dr7;
                if (read_debug_register(dbgee->pid, DR0_OFFSET, &dr0) != 0 ||
                    read_debug_register(dbgee->pid, DR1_OFFSET, &dr1) != 0 ||
                    read_debug_register(dbgee->pid, DR2_OFFSET, &dr2) != 0 ||
                    read_debug_register(dbgee->pid, DR3_OFFSET, &dr3) != 0 ||
                    read_debug_register(dbgee->pid, DR7_OFFSET, &dr7) != 0) {
                        (void)(fprintf(stderr,
                                       "Failed to read debug registers.\n"));
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
                        (void)(fprintf(stderr, "Hardware breakpoint address "
                                               "not found in DR0-DR3.\n"));
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
                        (void)(fprintf(stderr, "Invalid breakpoint number.\n"));
                        return EXIT_FAILURE;
                }

                if (set_debug_register(dbgee->pid, dr_offset, 0) != 0) {
                        (void)(fprintf(stderr, "Failed to clear DR%d.\n",
                                       dr_index));
                        return EXIT_FAILURE;
                }

                if (configure_dr7(dbgee->pid, dr_index, 0, 0, false) != 0) {
                        (void)(fprintf(
                            stderr,
                            "Failed to update DR7 after clearing DR%d.\n",
                            dr_index));
                        return EXIT_FAILURE;
                }

                printf("Hardware breakpoint removed at 0x%lx [Index: %zu, "
                       "DR%d]\n",
                       bp->data.hw_bp.address, index, dr_index);
        }

        if (remove_breakpoint(dbgee->bp_handler, index) != 0) {
                (void)(fprintf(stderr,
                               "Failed to remove breakpoint from handler.\n"));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

void ListBreakpoints(debuggee *dbgee) { list_breakpoints(dbgee->bp_handler); }

int Dump(debuggee *dbgee) {
        unsigned long rip;
        unsigned char buf[DUMP_SIZE];
        unsigned long base_address;
        char module_name[MODULE_NAME_SIZE] = {0};

        if (read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(stderr, "Failed to retrieve current RIP.\n"));
                return -1;
        }

        base_address = get_module_base_address(dbgee->pid, rip, module_name,
                                               sizeof(module_name));
        if (base_address == 0) {
                (void)(fprintf(stderr, "Failed to retrieve base address.\n"));
                return EXIT_FAILURE;
        }

        if (read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                (void)(fprintf(stderr, "Failed to read memory at 0x%lx\n",
                               rip));
                return EXIT_FAILURE;
        }

        printf("Memory dump in module '%s' at RIP: 0x%016lx (Offset: 0x%lx)\n",
               module_name, rip, rip - base_address);

        printf("---------------------------------------------------------------"
               "----------------------\n");
        printf("Offset              Hexadecimal                                "
               "      ASCII\n");
        printf("---------------------------------------------------------------"
               "----------------------\n");

        for (size_t i = 0; i < sizeof(buf); i += WORD_LENGTH) {
                unsigned long current_address = rip + i;
                unsigned long offset = current_address - base_address;
                printf("0x%016lx (0x%lx): ", current_address, offset);

                for (size_t j = 0; j < WORD_LENGTH; ++j) {
                        if (i + j < sizeof(buf)) {
                                printf("%02x ", buf[i + j]);
                        } else {
                                printf("   ");
                        }
                }

                printf(" ");
                for (size_t j = 0; j < WORD_LENGTH; ++j) {
                        if (i + j < sizeof(buf)) {
                                unsigned char c = buf[i + j];
                                printf("%c", (c >= ASCII_PRINTABLE_MIN &&
                                              c <= ASCII_PRINTABLE_MAX)
                                                 ? c
                                                 : '.');
                        }
                }

                printf("\n");
        }

        printf("---------------------------------------------------------------"
               "----------------------\n");

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

        if (read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(stderr, "Failed to retrieve current RIP.\n"));
                return EXIT_FAILURE;
        }

        base_address = get_module_base_address(dbgee->pid, rip, module_name,
                                               sizeof(module_name));
        if (base_address == 0) {
                (void)(fprintf(stderr, "Failed to retrieve base address.\n"));
                return EXIT_FAILURE;
        }

        if (read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                (void)(fprintf(stderr, "Failed to read memory at 0x%lx\n",
                               rip));
                return EXIT_FAILURE;
        }

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                (void)(fprintf(stderr, "Failed to initialize Capstone\n"));
                return EXIT_FAILURE;
        }

        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

        unsigned long offset = rip - base_address;
        printf("Disassembling memory in module '%s' at RIP: 0x%016lx (Offset: "
               "0x%lx)\n",
               module_name, rip, offset);

        count = cs_disasm(handle, buf, sizeof(buf), rip, 0, &insn);
        if (count > 0) {
                printf("-------------------------------------------------------"
                       "------------------------------\n");
                for (size_t i = 0; i < count; i++) {
                        unsigned long insn_offset =
                            insn[i].address - base_address;
                        printf("0x%016lx (0x%lx): %-10s\t%s\n", insn[i].address,
                               insn_offset, insn[i].mnemonic, insn[i].op_str);

                        if (strcmp(insn[i].mnemonic, "ret") == 0) {
                                break;
                        }
                }

                printf("-------------------------------------------------------"
                       "------------------------------\n");
                cs_free(insn, count);
        } else {
                (void)(fprintf(stderr, "Failed to disassemble given code!\n"));
        }

        cs_close(&handle);

        return EXIT_SUCCESS;
}

int Step(debuggee *dbgee) {
        if (ptrace(PTRACE_SINGLESTEP, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace SINGLESTEP");
                return EXIT_FAILURE;
        }
        dbgee->state = RUNNING;

        return EXIT_SUCCESS;
}

int StepOver(debuggee *dbgee) {
        unsigned long rip;
        if (read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(stderr, "Failed to read RIP for StepOver.\n"));
                return EXIT_FAILURE;
        }

        bool is_call = is_call_instruction(dbgee, rip);
        if (is_call) {

                // Set temporary breakpoint at the instruction after the call
                // instruction. On x86_64 we know that we need to add 5. 1 byte
                // for oppcode and 4 for the relative offset.
                unsigned long return_addr = rip + NEXT_INSTRUCTION_OFFSET;

                if (set_temp_sw_breakpoint(dbgee, return_addr) !=
                    EXIT_SUCCESS) {
                        (void)(fprintf(stderr, "Failed to set temporary "
                                               "breakpoint for StepOver.\n"));
                        return EXIT_FAILURE;
                }

                if (ptrace(PTRACE_CONT, dbgee->pid, NULL, NULL) == -1) {
                        perror("ptrace CONT");
                        return EXIT_FAILURE;
                }
                dbgee->state = RUNNING;

                return EXIT_SUCCESS;
        }

        return Step(dbgee);
}

int StepOut(debuggee *dbgee) {
        unsigned long return_address;

        if (get_return_address(dbgee, &return_address) != 0) {
                (void)fprintf(
                    stderr, "Failed to retrieve return address for StepOut.\n");
                return EXIT_FAILURE;
        }

        printf("Return address found at 0x%lx\n", return_address);

        if (set_temp_sw_breakpoint(dbgee, return_address) != EXIT_SUCCESS) {
                (void)fprintf(stderr,
                              "Failed to set temporary breakpoint at return "
                              "address 0x%lx.\n",
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

int DisplayGlobalVariables(debuggee *dbgee) {
        elf_symtab symtab_struct;
        if (!read_elf_symtab(dbgee->name, &symtab_struct)) {
                (void)(fprintf(stderr, "Failed to read ELF symbol tables.\n"));
                return EXIT_FAILURE;
        }

        printf("Global Variables with Values:\n");
        printf("---------------------------------------------------------------"
               "-----------------\n");
        printf("%-40s %-18s %-10s %-20s\n", "Name", "Address", "Size", "Value");
        printf("---------------------------------------------------------------"
               "-----------------\n");

        unsigned long base_address = get_load_base(dbgee);
        if (base_address == 0) {
                (void)(fprintf(stderr, "Failed to get base address.\n"));
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

                        printf("%-40s 0x%016lx %-10lu 0x%016lx\n", sym_name,
                               abs_address, sym.st_size, value);
                }
        }
        printf("---------------------------------------------------------------"
               "-----------------\n");

        for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                free(symtab_struct.entries[i].symtab);
                free(symtab_struct.entries[i].strtab);
        }
        free(symtab_struct.entries);
        return EXIT_SUCCESS;
}

int DisplayFunctionNames(debuggee *dbgee) {
        if (dbgee == NULL || dbgee->name == NULL) {
                (void)(fprintf(stderr, "Invalid debuggee or debuggee name.\n"));
                return EXIT_FAILURE;
        }

        elf_symtab symtab_struct;
        if (!read_elf_symtab(dbgee->name, &symtab_struct)) {
                (void)(fprintf(stderr, "Failed to read ELF symbol tables.\n"));
                return EXIT_FAILURE;
        }

        unsigned long base_address = get_load_base(dbgee);
        if (base_address == 0) {
                (void)(fprintf(stderr, "Failed to get base address.\n"));
                for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                        free(symtab_struct.entries[i].symtab);
                        free(symtab_struct.entries[i].strtab);
                }
                free(symtab_struct.entries);
                return EXIT_FAILURE;
        }

        printf("Function Names with Addresses:\n");
        printf("---------------------------------------------------------------"
               "-----------------\n");
        printf("%-40s %-18s %-10s\n", "Name", "Address", "Size");
        printf("---------------------------------------------------------------"
               "-----------------\n");

        for (size_t entry_idx = 0; entry_idx < symtab_struct.num_entries;
             entry_idx++) {
                elf_symtab_entry *entry = &symtab_struct.entries[entry_idx];
                for (size_t j = 0; j < entry->num_symbols; j++) {
                        Elf64_Sym sym = entry->symtab[j];

                        if ((ELF64_ST_TYPE(sym.st_info) != STT_FUNC) ||
                            (sym.st_shndx == SHN_UNDEF)) {
                                continue;
                        }

                        const char *sym_name = entry->strtab + sym.st_name;
                        if (sym_name == NULL || strlen(sym_name) == 0) {
                                continue;
                        }

                        unsigned long abs_address = base_address + sym.st_value;

                        printf("%-40s 0x%016lx %-10lu\n", sym_name, abs_address,
                               sym.st_size);
                }
        }

        printf("---------------------------------------------------------------"
               "-----------------\n");

        for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                free(symtab_struct.entries[i].symtab);
                free(symtab_struct.entries[i].strtab);
        }
        free(symtab_struct.entries);

        return EXIT_SUCCESS;
}

bool parse_breakpoint_argument(debuggee *dbgee, const char *arg,
                               uintptr_t *address_out) {
        if (arg == NULL || address_out == NULL) {
                (void)(fprintf(
                    stderr,
                    "Invalid arguments to parse_breakpoint_argument.\n"));
                return false;
        }

        if (arg[0] == '*') {
                unsigned long rip;
                unsigned long base_address;
                char module_name[MODULE_NAME_SIZE] = {0};

                char *endptr;
                uintptr_t offset = strtoull(arg + 1, &endptr, 0);
                if (*endptr != '\0') {
                        (void)(fprintf(stderr, "Invalid offset format: %s\n",
                                       arg + 1));
                        return false;
                }

                if (read_rip(dbgee, &rip) != 0) {
                        (void)(fprintf(stderr,
                                       "Failed to retrieve current RIP.\n"));
                        return false;
                }

                base_address = get_module_base_address(
                    dbgee->pid, rip, module_name, sizeof(module_name));
                if (base_address == 0) {
                        (void)(fprintf(stderr,
                                       "Failed to retrieve base address for "
                                       "offset calculation.\n"));
                        return false;
                }

                *address_out = base_address + offset;
        } else if (arg[0] == '&') {
                unsigned long func_offset = get_symbol_offset(dbgee, arg + 1);
                if (func_offset == 0) {
                        (void)(fprintf(stderr,
                                       "Failed to get func symbol offset.\n"));
                        return false;
                }

                unsigned long base_address = get_load_base(dbgee);
                if (base_address == 0) {
                        (void)(fprintf(stderr,
                                       "Failed to get base address.\n"));
                        return false;
                }

                *address_out = base_address + func_offset;
        } else {
                char *endptr;

                uintptr_t address = strtoull(arg, &endptr, 0);
                if (*endptr != '\0') {
                        (void)(fprintf(stderr, "Invalid address format: %s\n",
                                       arg));
                        return false;
                }

                *address_out = address;
        }

        return true;
}

int configure_dr7(pid_t pid, int bpno, int condition, int length, bool enable) {
        unsigned long dr7;

        if (read_debug_register(pid, DR7_OFFSET, &dr7) != 0) {
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

        return set_debug_register(pid, DR7_OFFSET, dr7);
}

int get_return_address(debuggee *dbgee, unsigned long *ret_addr_out) {
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

int set_debug_register(pid_t pid, unsigned long offset, unsigned long value) {
        if (ptrace(PTRACE_POKEUSER, pid, offset, value) == -1) {
                perror("ptrace POKEUSER DR7");
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

int read_debug_register(pid_t pid, unsigned long offset, unsigned long *value) {
        errno = 0;
        *value = ptrace(PTRACE_PEEKUSER, pid, offset, NULL);
        if (*value == (unsigned long)-1 && errno != 0) {
                perror("ptrace PEEKUSER debug register");
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

int set_rip(debuggee *dbgee, const unsigned long rip) {
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

int read_rip(debuggee *dbgee, unsigned long *rip) {
        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, dbgee->pid, NULL, &regs) == -1) {
                perror("ptrace GETREGS");
                return EXIT_FAILURE;
        }

        *rip = regs.rip;
        return EXIT_SUCCESS;
}

bool set_sw_breakpoint(pid_t pid, uint64_t addr, uint64_t *code_at_addr) {
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

int set_temp_sw_breakpoint(debuggee *dbgee, uint64_t addr) {
        uint64_t original_byte;
        if (!set_sw_breakpoint(dbgee->pid, addr, &original_byte)) {
                (void)(fprintf(stderr,
                               "Failed to set temporary breakpoint at 0x%lx.\n",
                               addr));
                return EXIT_FAILURE;
        }

        size_t bp_index =
            add_software_breakpoint(dbgee->bp_handler, addr, original_byte);
        if (bp_index == (size_t)-1) {
                (void)(fprintf(
                    stderr,
                    "Failed to add temporary breakpoint to handler.\n"));
                return EXIT_FAILURE;
        }

        dbgee->bp_handler->breakpoints[bp_index].temporary = true;

        return EXIT_SUCCESS;
}

int replace_sw_breakpoint(pid_t pid, uint64_t addr, uint64_t old_byte) {
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

int read_memory(pid_t pid, unsigned long address, unsigned char *buf,
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

bool is_software_breakpoint(debuggee *dbgee, size_t *bp_index_out) {
        unsigned long rip;
        if (read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(stderr, "Failed to retrieve current RIP.\n"));
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

int handle_software_breakpoint(debuggee *dbgee, size_t bp_index) {
        breakpoint *bp = &dbgee->bp_handler->breakpoints[bp_index];
        unsigned long address = bp->data.sw_bp.address;
        unsigned char original_byte = bp->data.sw_bp.original_byte;

        if (set_rip(dbgee, address) != 0) {
                (void)(fprintf(stderr,
                               "Failed to set current RIP to address 0x%lx.\n",
                               address));
                return EXIT_FAILURE;
        }

        if (replace_sw_breakpoint(dbgee->pid, address, original_byte) !=
            EXIT_SUCCESS) {
                (void)(fprintf(stderr,
                               "Failed to remove software breakpoint while "
                               "handling software breakpoint at 0x%lx\n",
                               address));
                return EXIT_FAILURE;
        }

        if (Step(dbgee) != 0) {
                (void)(fprintf(stderr, "Failed to single step.\n"));
                return EXIT_FAILURE;
        }

        int wait_status;
        if (waitpid(dbgee->pid, &wait_status, 0) == -1) {
                perror("waitpid");
                return EXIT_FAILURE;
        }

        if (WIFEXITED(wait_status)) {
                printf("Debuggee exited during single-step with status %d.\n",
                       WEXITSTATUS(wait_status));
                dbgee->state = TERMINATED;
                return EXIT_FAILURE;
        }

        if (WIFSIGNALED(wait_status)) {
                printf("Debuggee was killed by signal %d during single-step.\n",
                       WTERMSIG(wait_status));
                dbgee->state = TERMINATED;
                return EXIT_FAILURE;
        }

        if (WIFSTOPPED(wait_status)) {
                int sig = WSTOPSIG(wait_status);
                if (sig != SIGTRAP) {
                        (void)(fprintf(
                            stderr,
                            "Unexpected signal %d during single-step.\n", sig));
                        exit(EXIT_FAILURE);
                }
        }

        if (bp->temporary) {
                if (remove_breakpoint(dbgee->bp_handler, bp_index) != 0) {
                        (void)(fprintf(
                            stderr,
                            "Failed to remove temporary breakpoint at 0x%lx.\n",
                            address));
                        return EXIT_FAILURE;
                }
        } else {
                uint64_t original_data;
                if (!set_sw_breakpoint(dbgee->pid, address, &original_data)) {
                        (void)(fprintf(
                            stderr,
                            "Failed to re-insert software breakpoint while "
                            "handling software breakpoint at 0x%lx\n",
                            address));
                        return EXIT_FAILURE;
                }
        }

        return EXIT_SUCCESS;
}

int remove_all_breakpoints(debuggee *dbgee) {
        while (dbgee->bp_handler->count > 0) {
                size_t last_index = dbgee->bp_handler->count - 1;
                char index_str[INDEX_STR_MAX_LEN];

                if (snprintf(index_str, sizeof(index_str), "%zu", last_index) <
                    0) {
                        (void)(fprintf(stderr,
                                       "Failed to format breakpoint index.\n"));
                        return EXIT_FAILURE;
                }

                if (RemoveBreakpoint(dbgee, index_str) != EXIT_SUCCESS) {
                        (void)(fprintf(
                            stderr,
                            "Failed to remove breakpoint at index %zu.\n",
                            last_index));
                        return EXIT_FAILURE;
                }
        }
        return EXIT_SUCCESS;
}

bool breakpoint_exists(const debuggee *dbgee, unsigned long address) {
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

bool is_call_instruction(debuggee *dbgee, unsigned long rip) {
        unsigned char buf[MAX_X86_INSTRUCT_LEN];
        if (read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                (void)(fprintf(
                    stderr,
                    "Failed to read memory at 0x%lx for instruction check.\n",
                    rip));
                return false;
        }

        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                (void)(fprintf(
                    stderr,
                    "Failed to initialize Capstone for instruction check.\n"));
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

unsigned long get_load_base(debuggee *dbgee) {
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
                (void)(fprintf(
                    stderr, "Failed to find base address for %s in pid %d.\n",
                    dbgee->name, dbgee->pid));
        }

        return base_address;
}

unsigned long get_module_base_address(pid_t pid, unsigned long rip,
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
                               "Failed to find base address containing RIP "
                               "0x%lx in pid %d.\n",
                               rip, pid));
        }

        return base_address;
}

unsigned long get_symbol_offset(debuggee *dbgee, const char *symbol_name) {
        if (symbol_name == NULL) {
                (void)(fprintf(stderr, "Symbol name cannot be NULL.\n"));
                return 0;
        }

        elf_symtab symtab_struct;
        if (!read_elf_symtab(dbgee->name, &symtab_struct)) {
                (void)(fprintf(stderr, "Failed to read ELF symbol tables.\n"));
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
                (void)(fprintf(stderr, "'%s' symbol not found in %s.\n",
                               symbol_name, dbgee->name));
        }

        for (size_t i = 0; i < symtab_struct.num_entries; i++) {
                free(symtab_struct.entries[i].symtab);
                free(symtab_struct.entries[i].strtab);
        }
        free(symtab_struct.entries);

        return symbol_offset;
}

unsigned long get_main_absolute_address(debuggee *dbgee) {
        unsigned long main_offset = get_symbol_offset(dbgee, "main");
        if (main_offset == 0) {
                (void)(fprintf(stderr,
                               "Failed to get 'main' symbol offset.\n"));
                return 0;
        }

        unsigned long base_address = get_load_base(dbgee);
        if (base_address == 0) {
                (void)(fprintf(stderr, "Failed to get base address.\n"));
                return 0;
        }

        unsigned long main_absolute = base_address + main_offset;
        printf("'main' absolute address: 0x%lx\n", main_absolute);
        return main_absolute;
}
