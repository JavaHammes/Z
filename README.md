# Z Anti-Anti-Debugger

A debugger designed to bypass anti-debugging mechanisms with clear, precise control over program execution.

## Overview

Modern applications often implement advanced techniques to hinder debugging. Z Anti-Anti-Debugger is built to overcome these measures using a direct approach. Each command is designed to provide explicit control over the target program’s execution without unnecessary complexity.

## Build & Run

### Clone the Repository

Clone the repository along with its submodules:

```bash
git clone --recurse-submodules https://github.com/JavaHammes/Z.git
```

### Build with CMake

Generate the build files and compile the project:

```bash
cmake -B build
cmake --build build --clean-first
```

### Execute the Debugger

Navigate to the binary folder and start Z with your target executable:

```bash
cd bin
./z <target_executable>
```

Replace `<target_executable>` with the path to the program you wish to debug.

## Command Reference

### General Commands

```
help                - Display the help message
exit                - Quit the debugger
clear               - Clear the screen
log <filename>      - Begin logging output to the specified file
!!                  - Repeat the previous command
```

### Execution Commands

```
run                 - Start executing the target program
con                 - Continue execution after a pause
step                - Execute the next instruction
over                - Step over the current instruction
out                 - Step out of the current function
skip <n>            - Advance execution by n instructions
jump <addr>         - Jump to a specific address
jump *<offset>      - Jump to base_address + offset
jump &<func_name>   - Jump to the address of a function
trace <addr>        - Begin tracing from the given address
trace *<offset>     - Trace from base_address + offset
trace &<func_name>  - Trace from a function's address
```

### Breakpoint Commands

```
points              - List all breakpoints
break <addr>        - Set a software breakpoint at the specified address
break *<offset>     - Set a software breakpoint at base_address + offset
break &<func_name>  - Set a breakpoint at a function's address
hbreak <addr>       - Set a hardware breakpoint at the specified address
hbreak *<offset>    - Set a hardware breakpoint at base_address + offset
hbreak &<func_name> - Set a hardware breakpoint at a function's address
watch <addr>        - Monitor a memory address for read/write access
watch *<offset>     - Monitor base_address + offset for access
watch &<var_name>   - Monitor a global variable for changes
catch <sig/event>   - Catch a signal or process event
remove <idx>        - Remove the breakpoint at the given index
```

### Inspection Commands

```
regs                - Display CPU registers
dump                - Dump memory at the current instruction pointer
dis                 - Disassemble code at the current instruction pointer
vars                - Show global variables and their values
funcs               - List functions with their addresses
addr <func_name>    - Display the address of the specified function
backt               - Print a call stack backtrace
```

### Modification Commands

```
set <reg>=<value>   - Set the value of a register
patch <addr>=<hex>  - Patch memory at the specified address with hexadecimal opcodes
```

## Contributing

Contributions to improve this tool are welcome. Please fork the repository, open an issue, or submit a pull request with your proposed changes.

## License

This project is released under the MIT License. You are free to use, modify, and distribute it according to the terms of this license.
