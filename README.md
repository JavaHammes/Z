```

░▒▓████████▓▒░       ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓██████▓▒░   ░▒▓███████▓▒░  ░▒▓███████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
     ░▒▓██▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓██▓▒░           ░▒▓██████▓▒░   ░▒▓██████▓▒░  ░▒▓███████▓▒░  ░▒▓███████▓▒░  ░▒▓████████▓▒░ 
 ░▒▓██▓▒░            ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░        ░▒▓█▓▒░ 
░▒▓█▓▒░              ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░        ░▒▓█▓▒░ 
░▒▓████████▓▒░       ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓██████▓▒░   ░▒▓██████▓▒░   ░▒▓██████▓▒░         ░▒▓█▓▒░ 
                                                                                                
                                                                                                            
```

# Z Anti-Anti-Debugger

A no-frills debugger engineered for clarity, precision, and raw control.

## Overview

Modern applications often deploy sophisticated defenses to thwart debugging attempts. Z Anti-Anti-Debugger bypasses these obstacles with a direct, unembellished approach. Every command is designed to give you clear, explicit control over program execution - nothing more, nothing less.

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

Every command is designed for precision and clarity.

### General Commands

```
help                - Display this help message
exit                - Quit the debugger
clear               - Clear the screen
log <filename>      - Start logging output to the specified file
!!                  - Repeat the previous command
```

### Execution Commands

```
run                 - Start executing the target program
con                 - Continue execution after a pause
step                - Execute the next instruction
over                - Step over the current instruction
out                 - Step out of the current function
skip <n>            - Advance by n instructions
jump <addr>         - Jump to a specific address
jump *<offset>      - Jump to base_address + offset
jump &<func_name>   - Jump to the address of a function
trace <addr>        - Begin tracing at the given address
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

Contributions are welcome. Fork the repository, open an issue, or submit a pull request to help enhance Z Anti-Anti-Debugger. Your improvements make this tool even more effective for everyone.

## License

This project is released under the MIT License. Use, modify, and distribute it freely.

**Happy debugging!**
