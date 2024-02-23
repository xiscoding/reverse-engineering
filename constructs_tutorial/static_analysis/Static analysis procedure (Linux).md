## Goal: 
Identify file format, strings used, file size, possible dependencies, develop basic understanding of program flow and execution. 

• Image base  
	• The preferred address for the binary to be loaded  
• Entry point  
	• Address of the first bytes to execute once loaded into memory  
• Virtual Address  
	• Actual memory address (in PE parlance)  
• Relative Virtual Address  
	• An offset in memory, relative to where the PE file was loaded
## Linux tools:
1. File
	1. Get basic information about file type
	3. **file unknown2.bin**
		**Output:**
		- **`unknown2.bin: ELF 32-bit LSB pie executable`:**
		    - **ELF:** Executable and Linkable Format, a common format for executable files on Linux systems.
		    - **32-bit:** It's a 32-bit binary, meaning it's designed to run on a 32-bit processor architecture.
		    - **LSB:** Least Significant Byte first, indicating byte order for multi-byte values.
		    - **pie executable:** Position-Independent Executable, meaning it can be loaded at different memory addresses without issues, enhancing security.
		- **Intel 80386:** The binary is specifically compiled for Intel 80386 or compatible processors.
		- **version 1 (SYSV):** ELF version 1, using System V ABI (Application Binary Interface).
		- **dynamically linked:** It depends on external libraries to be loaded at runtime.
		- **interpreter /lib/ld-linux.so.2:** The dynamic linker/loader responsible for loading shared libraries is `/lib/ld-linux.so.2`.
		- **for GNU/Linux 3.2.0:** Built for the GNU/Linux operating system kernel version 3.2.0.
		- **BuildID[sha1]=b829793995d6861ec3032d2c88ed61862019abd4:** A unique identifier for the build process, useful for debugging or identifying specific builds.
		- **not stripped:** The debugging symbols (useful for reverse engineering) have not been removed from the binary.
2. readelf 
	1. Get basic information about file contents, headers, etc
	2. **readelf -h unknown2.bin**
	3. **readelf -s unknown2.bin** 
		1. get hexdump of all sections
3. strings
	1. view strings in file
	2. 
4. xxd
	1. View hexdump, see strings, edit strings
	2. edit 
		1. `echo: "[addresss to visit] : <Hexadecimal>" | xxd -r - <filename>`
5. objdump
	1. view disassembled file (-M intel) x86, amd64, intel syntax, att syntax, etc
		1. Show disassembled x86 file in intel syntax
		2. `objdump -M intel -d <filename>`
6. Ghidra
	1. does everything all these tools do and so much more
	2. Starting with ghidra is confusing you also may not be able to use the tool 
	3. Good idea to at least get file type, file/section/program headers, and pass through objdump quickly to make sure the file can be analyzed.
## General analysis procedure
file -> strings -> readelf -> xxd -> objdump (maybe)
Example below: file -> readelf -> objdump
**1. Initial Analysis with `file` and `readelf`:**

- **`file <unknown_binary>`:**
    - Determine the basic file type (ELF executable, shared library, etc.).
    - Identify the architecture (x86, ARM, etc.).
    - Check for any specific information like "not stripped" (debugging symbols present).
- **`readelf -S <unknown_binary>`:**
    - Examine section names (`.text`, `.data`, `.bss`) to understand basic structure.
    - Look for sections like `.rodata` (read-only data) or `.note` (additional information).
    - Check symbol presence (useful for function/variable names if not stripped).
- **`readelf -h <unknown_binary>`**
	- Find entry point, start of program, section headers
	- confirm file type and data format from file

**2. Deeper Inspection with `objdump`:**

- **`objdump -d <unknown_binary>`:**
    - Disassemble sections like `.text` to view assembly instructions.
    - Identify system calls or library function calls to understand interactions.
    - Look for patterns or recurring strings that might indicate functionality.
- **`objdump -s <unknown_binary>`:**
    - Analyze symbol table (if present) to identify functions and potential entry points.
    - Correlate symbol names with disassembled code for better understanding.

**3. Interactive Exploration with Ghidra:**

- Import the binary into Ghidra and explore the decompiled code (if available).
- Analyze data structures and function calls to understand program flow.
- Use Ghidra's search and analysis features to identify specific functionality like string manipulation, network interactions, or file I/O.
- Set breakpoints and debug the program (if possible) to observe its behavior in action.

**Information to Look For:**

- **System calls and library calls:** These reveal how the program interacts with the operating system and external libraries, providing clues about its functionality.
- **Strings and data structures:** Textual data and defined data structures can hint at the program's purpose and the type of information it processes.
- **Control flow and logic:** Analyze how the program makes decisions and branches based on conditions and user input.
- **Entry point and main function:** Identifying where the program starts execution and the central logic can provide a good starting point for understanding its overall behavior.

