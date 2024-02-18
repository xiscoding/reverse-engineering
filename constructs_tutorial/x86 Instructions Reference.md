#### [[MOV]]

- **Syntax**: `MOV destination, source`
- **Purpose**: Transfers data from the source to the destination. The source and destination can be registers, memory locations, or immediate values (constants), but both cannot be memory operands at the same time.
- **Usage Example**:
    - `MOV EAX, EBX` copies the contents of EBX into EAX.
    - `MOV AX, [myVar]` copies the contents of the memory location labeled `myVar` into AX.
#### MOVZX

- **Syntax**: `MOVZX destination, source`
- **Purpose**: Moves a byte or word from the source operand to the destination operand, zero-extending the value to fill the entire destination operand size. This instruction is typically used when moving data from a smaller-sized register or memory location to a larger-sized register.
- **Usage Example**:
    - `MOVZX EAX, AL` moves the value in the AL register (8 bits) to the EAX register (32 bits), zero-extending the value in the process.
#### LEA

- **Syntax**: `LEA destination, source`
- **Purpose**: Computes the effective address of the source operand (typically a memory location) and stores the result (the address) in the destination operand (usually a register). Unlike MOV, LEA does not access memory; it performs arithmetic operations on addresses.
- **Usage Example**:
    - `LEA EAX, [myArray + EBX*4]` computes the address of `myArray + EBX*4` and stores it in the EAX register.
#### [[PUSH]]

- **Syntax**: `PUSH source`
- **Purpose**: Decrements the stack pointer (SP or ESP) by the size of the source operand (typically 2 or 4 bytes on x86) and then stores the value of the source operand at the top of the stack.
- **Usage Example**:
    - `PUSH EAX` saves the value in EAX onto the stack.
#### [[ADD]]

- **Syntax**: `ADD destination, source`
- **Purpose**: Adds the value of the source operand to the destination operand and stores the result in the destination operand. Both operands can be registers, memory locations, or immediate values.
- **Usage Example**:
    - `ADD EAX, EBX` adds the value in EBX to the value in EAX and stores the result in EAX.
#### SUB

- **Syntax**: `SUB destination, source`
- **Purpose**: Subtracts the value of the source operand from the destination operand and stores the result in the destination operand.
- **Usage Example**:
    - `SUB ESP, 4` decreases the stack pointer by 4, effectively allocating 4 bytes on the stack.
#### [[CMP]]

- **Syntax**: `CMP operand1, operand2`
- **Purpose**: Compares the values of the two operands without modifying them. It sets the appropriate flags in the EFLAGS register based on the result of the comparison (equal, less than, greater than).
- **Usage Example**:
    - `CMP EAX, EBX` compares the values in EAX and EBX registers without changing either value.
#### JA

- **Syntax**: `JA target`
- **Purpose**: Jumps to the specified target if the condition is met. Specifically, it jumps if the "above" condition is true, meaning if the unsigned comparison result was greater than (above) when using CMP or similar instructions.
- **Usage Example**:
    - `JA label1` jumps to `label1` if the unsigned comparison result indicated that the first operand was above the second operand.
#### JS

- **Syntax**: `JS target`
- **Purpose**: The `JS` (Jump if Sign) instruction transfers control to the target label or address if the sign flag (SF) in the EFLAGS register is set. The sign flag is set by the result of the last arithmetic or logical instruction (such as `TEST`, `SUB`, `ADD`, etc.) if the result was negative when interpreted as a signed number.
- **Usage**: `JS` is used for conditional branching based on the sign of the last operation's result. It is particularly useful in signed arithmetic operations where the outcome of a calculation's sign (positive or negative) determines the flow of execution.
- **Usage Example**:
    - After performing a `SUB` or `TEST` instruction that results in a negative value, `JS label` would jump to the `label` if the result was negative, indicating that the sign flag was set.
#### [[JNZ]]

- **Syntax**: `JNZ target`
- **Purpose**: Jumps to the specified target if the condition is met. Specifically, it jumps if the "not zero" condition is true, meaning if the result of a previous operation was not zero (non-zero).
- **Usage Example**:
    - `JNZ label1` jumps to `label1` if the result of a previous operation (typically the result of a CMP instruction) was not zero.
#### [[JMP]]

- **Syntax**: `JMP target`
- **Purpose**: Unconditionally jumps to the specified target, changing the flow of execution to a different part of the program.
- **Usage Example**:
    - `JMP myFunction` transfers control to the `myFunction` label or memory address, regardless of any conditions.
#### JLE

- **Syntax**: `JLE target`
- **Purpose**: Jumps to the specified target if the condition is met. Specifically, it jumps if the "less than or equal" condition is true, meaning if the signed comparison result was less than or equal when using CMP or similar instructions.
- **Usage Example**:
    - `JLE label1` jumps to `label1` if the signed comparison result indicated that the first operand was less than or equal to the second operand.
#### JNE

- **Syntax**: `JNE target`
- **Purpose**: Jumps to the specified target if the condition is met. Specifically, it jumps if the "not equal" condition is true, meaning if the comparison result indicated that the two operands are not equal when using CMP or similar instructions.
- **Usage Example**:
    - `JNE label1` jumps to `label1` if the comparison result indicated that the two operands are not equal.
#### [[CDQ]]

- **Syntax**: `CDQ`
- **Purpose**: Sign extends the EAX register into the EDX register, preparing for operations like `IDIV` that require a double-width operand. Specifically, it copies the sign (most significant bit) of EAX into every bit of EDX.
- **Usage Example**:
    - Before executing `IDIV EBX`, `CDQ` ensures that EDX:EAX forms a valid 64-bit integer.
#### [[IDIV]]

- **Syntax**: `IDIV operand`
- **Purpose**: Performs signed division using the accumulator. If `operand` is a 32-bit register, EDX:EAX is divided by the operand, with the quotient stored in EAX and the remainder in EDX.
- **Usage Example**:
    - `IDIV ECX` divides the 64-bit integer in EDX:EAX by ECX, with the result in EAX and the remainder in EDX.
#### FLD

- **Syntax**: `FLD source`
- **Purpose**: Loads a floating-point value from the specified source into the top of the floating-point stack (FPU stack). The source can be a memory location containing a floating-point number. The instruction supports various floating-point formats, including single-precision (32-bit), double-precision (64-bit), and extended precision (80-bit).
- **Usage Example**:
    - `FLD DWORD PTR [myFloat]` loads a 32-bit floating-point value from the memory location labeled `myFloat` onto the top of the FPU stack.
    - `FLD QWORD PTR [myDouble]` loads a 64-bit double-precision floating-point value from the memory location labeled `myDouble` onto the top of the FPU stack.
#### FSTP

- **Syntax**: `FSTP destination`
- **Purpose**: Stores the value at the top of the floating-point stack (FPU stack) into the destination operand, and then pops the value from the stack.
- **Usage Example**:
    - `FSTP DWORD PTR [myFloat]` stores the top value from the FPU stack into the memory location labeled `myFloat` as a 32-bit floating-point value.
#### XCHG

- **Syntax**: `XCHG operand1, operand2`
- **Purpose**: Exchanges the values of the two operands without using additional temporary storage. Both operands can be registers or memory locations, but they cannot both be memory operands.
- **Usage Example**:
    - `XCHG EAX, EBX` exchanges the values in EAX and EBX registers.
#### NOP

- **Syntax**: `NOP`
- **Purpose**: No operation. It is a placeholder instruction that does nothing. It is often used for padding or as a placeholder for code that will be added later.
- **Usage Example**:
    - `NOP` is simply a placeholder instruction that occupies space in the code segment without performing any meaningful operation.
#### [[CALL]]

- **Syntax**: `CALL target`
- **Purpose**: Calls a procedure (function) by pushing the address of the next instruction (return address) onto the stack and then jumping to the target procedure's starting address.
- **Usage Example**:
    - `CALL myFunction` calls the procedure `myFunction`.
#### RET

- **Syntax**: `RET` or `RET imm16`
- **Purpose**: Returns from a procedure by popping the top of the stack into the instruction pointer (IP or EIP), optionally adding an immediate value to the stack pointer to adjust for arguments pushed onto the stack.
- **Usage Example**:
    - `RET` returns to the calling procedure.
    - `RET 4` cleans up 4 bytes of arguments from the stack after returning.
#### LEAVE

- **Syntax**: `LEAVE`
- **Purpose**: High-level instruction used at the end of a procedure to reset the stack frame. It moves the base pointer (EBP) value into the stack pointer (ESP), effectively dismantling the local stack frame, and then pops the old base pointer off the stack.
- **Usage Example**:
    - Typically used in the epilogue of a function to restore the stack frame of the caller before a `RET` instruction.
#### TEST

- **Syntax**: `TEST operand1, operand2`
- **Purpose**: The `TEST` instruction performs a bitwise AND operation on the two operands but does not store the result; instead, it updates the flags in the EFLAGS register based on the result of the operation. It is primarily used to set or clear the zero flag (ZF) and the sign flag (SF) without modifying the operands. This is useful for conditional branching based on the presence or absence of certain bits in a register or memory location.
- **Usage**: `TEST` is often used to test specific bits within operands by performing a bitwise AND with a mask. For example, testing if a register's value is odd or even, or checking for specific flag bits being set.
- **Usage Example**:
    - `TEST EAX, EAX` is a common idiom to test if the `EAX` register is zero. If `EAX` is zero, the ZF flag is set.
    - `TEST AL, 1` tests the least significant bit of the AL register to determine if the value is odd or even. If AL is odd, the ZF flag is clear; if AL is even, the ZF flag is set.
### OFFSET

- **Purpose**: In assembly language, the `OFFSET` keyword is used to obtain the address (not the value) of a variable, label, or function. It's a way to directly access memory addresses, which is essential for operations that require the address of data rather than the data itself.
- **Usage**: `OFFSET` is often used in instructions to load or manipulate the address of data structures, variables, or functions into registers for indirect access or manipulation.
### FLAT Memory Model

- **FLAT Model**: The term "FLAT" refers to a flat memory model. In the context of modern computing architectures, especially those running on x86 and x64 platforms under operating systems like Windows, Linux, or macOS, a flat memory model is one in which programs perceive memory as a continuous and unsegmented block. This model contrasts with segmented memory models, where memory is divided into segments with different base addresses.
- **Purpose**: The flat memory model simplifies programming and memory management by allowing all pointers to be treated as direct addresses within a single, contiguous memory space. This is the standard memory model for 32-bit and 64-bit applications.
### OFFSET FLAT in Assembly Code

- **Combination Usage**: When you encounter `OFFSET FLAT` together in assembly language, especially in disassembled output or compiler-generated assembly, it typically pertains to accessing the address of a symbol (like a function or variable) in a flat memory model environment. The `FLAT` part indicates that the address calculation is being done in the context of a flat memory model, and `OFFSET` is getting the address of the symbol.
- **Example**: Seeing `OFFSET FLAT:myVariable` or similar syntax in disassembly or assembly output suggests that the instruction is obtaining the address of `myVariable` within a flat memory model space. This is common in systems where the memory model does not require segment:offset pairs for addressing.
### Practical Implication

In practical assembly language coding or when reading compiler-generated assembly, understanding that `OFFSET` gets the address and that `FLAT` refers to the flat memory model helps in comprehending how the application interacts with memory. It essentially means the code is operating with direct, linear addresses, simplifying the process of data access and manipulation in modern programming environments.