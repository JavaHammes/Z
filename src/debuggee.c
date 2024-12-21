#include <capstone/capstone.h>
#include <ctype.h>
#include <errno.h>
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
        INT3 = 0xCC,
        RESPONSE_BUFFER_SIZE = 10,
        BYTE_MASK = 0xFFUL,
        INDEX_STR_MAX_LEN = 20,
};

static inline unsigned long DR7_ENABLE_LOCAL(int bpno) {
        return 0x1UL << (bpno * 2);
}

static inline unsigned long DR7_RW_WRITE(int bpno) {
        return 0x1UL << (WORD_LENGTH + (bpno * 4));
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

                if (answer == 'y') {
                        return true;
                }
        }

        return false;
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
        printf("---------------------------------------------------------------"
               "\n");

        printf("Execution Commands:\n");
        printf("---------------------------------------------------------------"
               "\n");
        printf("  run             - Run the debuggee program\n");
        printf("  con             - Continue execution of the debuggee\n");
        printf(
            "  step            - Execute the next instruction (single step)\n");
        printf("  over            - Step over the current instruction\n");
        printf("  out             - Step out of the current function\n");
        printf("---------------------------------------------------------------"
               "\n");

        printf("Breakpoint Commands:\n");
        printf("---------------------------------------------------------------"
               "\n");
        printf("  points          - List all breakpoints\n");
        printf("  break <addr>    - Set a software breakpoint at <addr>\n");
        printf("  hbreak <addr>   - Set a hardware breakpoint at <addr>\n");
        printf("  remove <idx>    - Remove the breakpoint at index <idx>\n");
        printf("---------------------------------------------------------------"
               "\n");

        printf("Inspection Commands:\n");
        printf("---------------------------------------------------------------"
               "\n");
        printf("  regs            - Display CPU registers (general-purpose and "
               "debug)\n");
        printf("  dump            - Dump memory at the current instruction "
               "pointer\n");
        printf("  dis             - Disassemble memory at the current "
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
                        printf("Continuing execution with existing "
                               "breakpoints.\n");
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
        uintptr_t address = strtoull(arg, NULL, 0);
        if (address == 0) {
                (void)(fprintf(stderr, "Invalid address: %s\n", arg));
                return EXIT_FAILURE;
        }

        unsigned char original_byte;
        if (read_memory(dbgee->pid, address, &original_byte, 1) != 0) {
                (void)(fprintf(stderr,
                               "Failed to read memory at address 0x%lx\n",
                               address));
                return EXIT_FAILURE;
        }

        if (write_memory_byte(dbgee->pid, address, INT3) != 0) {
                (void)(fprintf(stderr,
                               "Failed to set software breakpoint at 0x%lx\n",
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
        uintptr_t address = strtoull(arg, NULL, 0);
        if (address == 0) {
                (void)(fprintf(stderr, "Invalid address: %s\n", arg));
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
                (void)(fprintf(stderr,
                        "No available hardware breakpoint registers.\n"));
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

        if (configure_dr7(dbgee->pid, bpno, 0x0, 0x0) != 0) { // condition=00 (execute), length=00 (1 byte)
                (void)(fprintf(stderr, "Failed to configure DR7 for breakpoint %d.\n",
                        bpno));
                return EXIT_FAILURE;
        }

        size_t bp_index = add_hardware_breakpoint(dbgee->bp_handler, address);
        printf("Hardware breakpoint set at 0x%lx [Index: %zu, DR%d]\n", address,
               bp_index, bpno);

        return EXIT_SUCCESS;
}

int RemoveBreakpoint(debuggee *dbgee, const char *arg) {
        size_t index = strtoull(arg, NULL, RESPONSE_BUFFER_SIZE);
        if (index >= dbgee->bp_handler->count) {
                (void)(fprintf(stderr, "Invalid breakpoint index: %zu\n",
                               index));
                return EXIT_FAILURE;
        }

        breakpoint *bp = &dbgee->bp_handler->breakpoints[index];

        if (bp->bp_t == SOFTWARE_BP) {
                if (write_memory_byte(dbgee->pid, bp->data.sw_bp.address,
                                      bp->data.sw_bp.originalData) != 0) {
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

                unsigned long *dr = NULL;
                unsigned long dr_offset;
                switch (dr_index) {
                case 0:
                        dr = &dr0;
                        dr_offset = DR0_OFFSET;
                        break;
                case 1:
                        dr = &dr1;
                        dr_offset = DR1_OFFSET;
                        break;
                case 2:
                        dr = &dr2;
                        dr_offset = DR2_OFFSET;
                        break;
                case 3:
                        dr = &dr3;
                        dr_offset = DR3_OFFSET;
                        break;
                default:
                        dr = NULL;
                        break;
                }

                if (dr == NULL) {
                        (void)(fprintf(stderr,
                                       "Invalid debug register index.\n"));
                        return EXIT_FAILURE;
                }

                *dr = 0;

                if (set_debug_register(dbgee->pid, dr_offset, *dr) != 0) {
                        (void)(fprintf(stderr, "Failed to clear DR%d.\n",
                                       dr_index));
                        return EXIT_FAILURE;
                }

                /*
                if (configure_dr7(dbgee->pid, dr_index) != 0) {
                        (void)(fprintf(
                            stderr,
                            "Failed to update DR7 after clearing DR%d.\n",
                            dr_index));
                        return EXIT_FAILURE;
                }
                */

                printf(
                    "Hardware breakpoint removed at 0x%lx [Index: %zu, DR%d]\n",
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

        if (read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(stderr, "Failed to retrieve current RIP.\n"));
                return -1;
        }

        if (read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                (void)(fprintf(stderr, "Failed to read memory at 0x%lx\n",
                               rip));
                return EXIT_FAILURE;
        }

        printf("Memory dump at 0x%016lx:\n", rip);
        printf("---------------------------------------------------------------"
               "----------------------\n");
        printf("Offset              Hexadecimal                                "
               "      ASCII\n");
        printf("---------------------------------------------------------------"
               "----------------------\n");

        for (size_t i = 0; i < sizeof(buf); i += WORD_LENGTH) {
                printf("0x%016lx: ", rip + i);

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

        if (read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(stderr, "Failed to retrieve current RIP.\n"));
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

        printf("Disassembling memory at current RIP: 0x%016lx\n", rip);

        count = cs_disasm(handle, buf, sizeof(buf), rip, 0, &insn);
        if (count > 0) {
                printf("-------------------------------------------------------"
                       "------------------------------\n");
                for (size_t i = 0; i < count; i++) {
                        // printf("0x%016llx: %s\t\t%s\n",
                        printf("0x%016llx: %-10s\t%s\n",
                               (unsigned long long)insn[i].address,
                               insn[i].mnemonic, insn[i].op_str);
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

        return EXIT_SUCCESS;
}

// Are equal to "Step" for now.
// Need to implement breakpoints first.
// TODO: implement
int StepOver(debuggee *dbgee) {
        if (ptrace(PTRACE_SINGLESTEP, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace SINGLESTEP");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

// TODO: implement
int StepOut(debuggee *dbgee) {
        if (ptrace(PTRACE_SINGLESTEP, dbgee->pid, NULL, NULL) == -1) {
                perror("ptrace SINGLESTEP");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

int configure_dr7(pid_t pid, int bpno, int condition, int length) {
    unsigned long dr7;

    if (read_debug_register(pid, DR7_OFFSET, &dr7) != 0) {
        return EXIT_FAILURE;
    }

    dr7 |= DR7_ENABLE_LOCAL(bpno);
    dr7 &= ~(0xF << (16 + bpno * 4));
    dr7 |= (condition & 0x3) << (16 + bpno * 4);
    dr7 |= (length & 0x3) << (18 + bpno * 4);

    return set_debug_register(pid, DR7_OFFSET, dr7);
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

int set_debug_register(pid_t pid, unsigned long offset, unsigned long value) {
        if (ptrace(PTRACE_POKEUSER, pid, offset, value) == -1) {
                perror("ptrace POKEUSER DR7");
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

int write_memory_byte(pid_t pid, unsigned long address, uint8_t byte) {
        errno = 0;
        unsigned long word =
            ptrace(PTRACE_PEEKDATA, pid, address & ~(sizeof(long) - 1), NULL);
        if (word == (unsigned long)-1 && errno != 0) {
                perror("ptrace PEEKDATA");
                return EXIT_FAILURE;
        }

        size_t byte_offset = address % sizeof(long);
        word = (word & ~(BYTE_MASK << (BYTE_LENGTH * byte_offset))) |
               ((unsigned long)byte << (BYTE_LENGTH * byte_offset));

        if (ptrace(PTRACE_POKEDATA, pid, address & ~(sizeof(long) - 1), word) ==
            -1) {
                perror("ptrace POKEDATA");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

bool is_software_breakpoint(debuggee *dbgee, size_t *bp_index_out) {
        unsigned long rip;
        if (read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(stderr, "Failed to retrieve current RIP.\n"));
                return -1;
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
        unsigned char original_byte = bp->data.sw_bp.originalData;

        // 1: Restore the original byte at breakpoint address
        if (write_memory_byte(dbgee->pid, address, original_byte) != 0) {
                (void)(fprintf(stderr,
                               "Failed to restore original byte at 0x%lx\n",
                               address));
                return EXIT_FAILURE;
        }

        // 2: Adjust RIP to point back to the breakpoint address
        if (set_rip(dbgee, address) != 0) {
                (void)(fprintf(stderr,
                               "Failed to set current RIP to address 0x%lx.\n",
                               address));
                return EXIT_FAILURE;
        }

        // 3: Single-step the instruction
        if (Step(dbgee) != 0) {
                (void)(fprintf(stderr, "Failed to single step.\n"));
                return EXIT_FAILURE;
        }

        // 4: Wait for the single-step to complete
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
                        exit(EXIT_FAILURE);
                }
        }

        // 5: Re-insert the INT3 opcode to maintain the breakpoint
        if (write_memory_byte(dbgee->pid, address, INT3) != 0) {
                (void)(fprintf(stderr,
                               "Failed to set software breakpoint at 0x%lx\n",
                               address));
                return EXIT_FAILURE;
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
