#include <capstone/capstone.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "debuggee.h"

#define DR0_OFFSET offsetof(struct user, u_debugreg[0])
#define DR1_OFFSET offsetof(struct user, u_debugreg[1])
#define DR2_OFFSET offsetof(struct user, u_debugreg[2])
#define DR3_OFFSET offsetof(struct user, u_debugreg[3])
#define DR7_OFFSET offsetof(struct user, u_debugreg[7])

#define TEST_BREAKPOINT_ADDR 0x11c9
#define DR7_ENABLE_LOCAL(bpno) (0x1 << ((bpno) * 2))
#define DR7_RW_WRITE(bpno) (0x1 << (16 + (bpno) * 4))

#define DUMP_SIZE 128
#define WORD_LENGTH 16
#define BYTE_LENGTH 8
#define MAX_BYTE_VALUE 0xFF

void Help(void) {
        printf("Z Anti-Anti-Debugger:\n");
        printf("Available commands:\n");
        printf("  help        - Display this help message\n");
        printf("  exit        - Exit the debugger\n");
        printf("  run         - Run the debuggee program\n");
        printf("  registers   - Display CPU registers (general-purpose and "
               "debug registers) of the debuggee\n");
        printf("  dump        - Dump memory at current RIP.\n");
        printf("  dis         - Dump disassembled memory at current RIP.\n");
}

int Run(debuggee *dbgee) {
        if (dbgee->state != STOPPED) {
                (void)(fprintf(
                    stderr,
                    "Debuggee is not in a stopped state. Current state: %d\n",
                    dbgee->state));
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
        printf("R15: 0x%llx\n", regs.r15);
        printf("R14: 0x%llx\n", regs.r14);
        printf("R13: 0x%llx\n", regs.r13);
        printf("R12: 0x%llx\n", regs.r12);
        printf("R11: 0x%llx\n", regs.r11);
        printf("R10: 0x%llx\n", regs.r10);
        printf("R9:  0x%llx\n", regs.r9);
        printf("R8:  0x%llx\n", regs.r8);
        printf("RAX: 0x%llx\n", regs.rax);
        printf("RBX: 0x%llx\n", regs.rbx);
        printf("RCX: 0x%llx\n", regs.rcx);
        printf("RDX: 0x%llx\n", regs.rdx);
        printf("RSI: 0x%llx\n", regs.rsi);
        printf("RDI: 0x%llx\n", regs.rdi);
        printf("RBP: 0x%llx\n", regs.rbp);
        printf("RSP: 0x%llx\n", regs.rsp);
        printf("RIP: 0x%llx\n", regs.rip);
        printf("EFL: 0x%llx\n", regs.eflags);
        printf("CSGSFS: 0x%llx\n", regs.cs);
        printf("DR0: 0x%016lx\n", dr0);
        printf("DR1: 0x%016lx\n", dr1);
        printf("DR2: 0x%016lx\n", dr2);
        printf("DR3: 0x%016lx\n", dr3);
        printf("DR7: 0x%016lx\n", dr7);

        return EXIT_SUCCESS;
}

int Hbreak(debuggee *dbgee) {
        // Note: this is not final. This is just for testing the Registers
        // method.
        unsigned long addr = TEST_BREAKPOINT_ADDR;
        int bpno = 0;

        if (configure_dr7(dbgee->pid, bpno) != 0) {
                return EXIT_FAILURE;
        }

        if (set_debug_register(dbgee->pid, DR0_OFFSET, addr) == -1) {
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

int Dump(debuggee *dbgee) {
        unsigned long rip;
        unsigned char buf[DUMP_SIZE];

        if (read_rip(dbgee, &rip) != 0) {
                (void)(fprintf(stderr, "Failed to retrieve current RIP.\n"));
                return -1;
        }

        printf("Dumping memory at current RIP: 0x%016lx\n", rip);

        if (read_memory(dbgee->pid, rip, buf, sizeof(buf)) != 0) {
                (void)(fprintf(stderr, "Failed to read memory at 0x%lx\n",
                               rip));
                return EXIT_FAILURE;
        }

        printf("Memory dump at 0x%lx:\n", rip);

        for (size_t i = 0; i < sizeof(buf); i++) {
                if (i % WORD_LENGTH == 0) {
                        printf("0x%016lx: ", rip + i);
                }
                printf("%02x ", buf[i]);
                if ((i + 1) % WORD_LENGTH == 0 || i + 1 == sizeof(buf)) {
                        printf("\n");
                }
        }

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

        printf("Dumping memory at current RIP: 0x%016lx\n", rip);

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

        count = cs_disasm(handle, buf, sizeof(buf), rip, 0, &insn);
        if (count > 0) {
                for (size_t i = 0; i < count; i++) {
                        printf("0x%016llx: %s\t\t%s\n",
                               (unsigned long long)insn[i].address,
                               insn[i].mnemonic, insn[i].op_str);
                }
                cs_free(insn, count);
        } else {
                (void)(fprintf(stderr, "Failed to disassemble given code!\n"));
        }

        cs_close(&handle);

        return EXIT_SUCCESS;
}

int configure_dr7(pid_t pid, int bpno) {
        unsigned long dr7;
        read_debug_register(pid, DR7_OFFSET, &dr7);

        // Configure DR7 to enable the breakpoint
        // Example: Enable local breakpoint, condition on write, 1-byte length
        dr7 |= DR7_ENABLE_LOCAL(bpno); // Local enable for breakpoint bpno
        dr7 |= DR7_RW_WRITE(
            bpno); // RW=01 (Write), LEN=00 (1 byte) for breakpoint bpno

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
