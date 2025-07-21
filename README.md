# Z Anti-Anti-Debugger

A debugger designed to bypass anti-debugging mechanisms with clear, precise control over program execution.

## Overview

Modern applications often implement advanced techniques to hinder debugging. Z Anti-Anti-Debugger is built to overcome these measures using a direct approach. Each command is designed to provide explicit control over the target program’s execution without unnecessary complexity. Documentation: [https://javahammes.github.io/Z/](https://javahammes.github.io/Z/)

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
cd bin/
./z <target_executable> [ld_preload_library1 [ld_preload_library2 ...]]
```

- Replace `<target_executable>` with the path to the program you wish to debug.
- `[ld_preload_library1 [ld_preload_library2 ...]]`: Optional custom LD_PRELOAD libraries.

If no custom libraries are specified, the following 5 default libraries will be used:

- `libfopen_intercept.so`
- `libgetenv_intercept.so`
- `libprctl_intercept.so`
- `libptrace_intercept.so`
- `libsetvbuf_unbuffered.so`

#### Custom `LD_PRELOAD` Libraries

You can extend Z by supplying your own LD_PRELOAD libraries. **Important**: Each custom library must include the following marker function:

```C
void zZz() {}
```
This marker acts as a signature, signaling to Z’s default preload libraries that your library is custom, especially crucial when combining default and custom libraries.

For instance, in the `fopen` override, when processing files like `/proc/self/maps`, the library filters only the lines corresponding to libraries that include the **zZz** marker. This ensures that any of the debuggee’s own libraries present in `/proc/self/maps` aren’t mistakenly filtered out (which could alert the debuggee to the presence of a debugger). Without this marker, your custom library might not integrate properly, potentially leading to unfiltered or unexpected behavior in your `fopen` or `getenv` overrides.

## Command Reference

### General Commands

```
help                - Display the help message
exit                - Quit the debugger
clear               - Clear the screen
log <filename>      - Begin logging output to the specified file
preload             - Show preloaded libraries
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
