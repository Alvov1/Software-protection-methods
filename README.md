# Prevent-dissasembly-and-debugging
A test project on the basics of protecting software from debugging, disassembly and modification.


Unsafe project was modified with such additions:


1. Strings are crypted in the compile time;

2. Pass-check function immutability is checked by counting function's CRC;


3. Added five different methods for debugging detection such as:
- Checking debugger with IsDebuggerPresent();
- Checking BeingDebugged value in PEB structure;
- Checking NtGlobalFlag for debugger; 
- Checking heap flags and force flags;
- Checking NtQueryInformationProcess;

4. Added four different disassembly countermeasures:
- Added assembly instructions of conditional branches;
- Added garbage assembly instructions;
- Added some self-modified assembly code;
- Added macroses for changing unvaluable bytes to assembly instructions;

Created for MSVC/Windows Visual Studio compiler.
