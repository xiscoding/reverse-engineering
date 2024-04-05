[[x86 Instructions Reference]]

## Global vs Local Variables: 

Global variables can be accessed and used by any function in a program. 
Local variables can be accessed only by the function in which they are defined. 
 Both global and local variables are declared similarly in C, but they look completely different in assembly 

**Global variables** are **referenced by memory address**
**Local variables** are **referenced by stack address**
#### Global Variable C:
![[globalVariable_c.png]]
#### Global Variable Assembly:
any function that uses variable dword_40CF60 can access the variable x
![[globalVariable_ex.png]]

#### Local Variable in C:
![[localVariable_c.png]]

#### Local Variable Assembly:
![[localVariable_ex.png]]
**Labeling is also available: **
![[localVariable_labeling.png]]

## Arithmetic Example:
#### Arithmetic Example C code:
![[arithmeticC_ex.png]]
#### C example in Assembly:
![[arithmeticAssembly_ex.png]]
**SWITCH STATEMET** [[CDQ]] and [[IDIV]] instructions set up the division and remainder for the modulo operation.
- **implement the modulo**. When performing the div or idiv instruction, you are dividing edx:eax by the operand and storing the result in eax and the remainder in edx. That is why edx is moved into var_8
## If Statements:
Instructions: [[MOV]], [[CMP]], [[JNZ]], [[CMP]], [[PUSH]], [[CALL]], [[ADD]], [[JMP]], [[PUSH]]
**Features**: Single jump to location, not loop to beginning of section 
#### C code example: 
![[ifStatement_C_ex.png]]

#### Assembly If Statement:
![[ifStatement_assemblyEx.png]]
The **decision to jump** is made based on the comparison (cmp), which checks to see if var_4 equals var_8 (var_4 and var_8 correspond to x and y in our source code). 
If the values are not equal, the jump occurs, and the code prints "x is not equal to y."; otherwise, the code continues the path of execution and prints "x equals y."

### Nested if Statements

#### C code example:
![[nestedIf_c.png]]

#### Assembly nested if:
![[nestedif_assembly.png]]

## Recognizing Loops: 
**For loops always have four components:** *initialization*, *comparison*, *execution* instructions, and the *increment* or decrement

#### For Loop in C:
![[forLoop_C_ex.png]]
*Initialization*:  'i' is set to zero
*Comparison*: 'i' is compared to 100
*Execution*: While 'i' is less than 100, the loop will print a value
*Increment*: after each execution 'i' is incremented

#### For Loop in Assembly:
![[forLoop_Assembly_ex.png]]
*Initialization*: The first line is the initialization
```mov [ebp+var_4], 0```
*Comparison*:  comparison takes two lines of code
`cmp ebp+var_4, 64h`
`jge short loc_40102F`
*Execution*: If the jump is not taken the code portion of the loop executes
```Assembly
mov ecx, [ebp+var_4]
push ecx
push offset aID ; "i equals %d\n"
call printf
add exp, 8
```
*Increment*: after the execution is run the jump instruction is taken `jmp short loc_40100D` and the increment occurs
```Assembly
mov eax, [ebp+var_4]
add eax, 1
mov [ebp+var_4], eax
```
	
## Calling Conventions:  

Psudocode used to describe calling conventions: 
![[psuedocode_ch6.png]]
Cdecl, stdcall, fastcall 

### Cdecl: 
 ![[cdecl_functioncall.png]]
 

Parameters pushed on stack from right to left 

Caller cleans up stack 

Most popular calling convention 

### Stdcall: 

Parameters pushed on stack from right to left 

Callee cleans up stack 

Calling convention of Windows API 

### Fastcall: 

First few arguments are passed in registers (usually EDX, ECX) 

Additional arguments pushed to stack right to left 

Caller cleans up stack 

Sometimes more efficient as less stack pushing 

### Push vs. Move: 
![[twoDiffCallingConventions.png]]

Commands used may vary between calling conventions 

## Analyzing switch Statements:  

switch statements are used by programmers (and malware authors) to make a decision based on a character or integer. For example, backdoors commonly select from a series of actions using a single byte value 

Usually, two ways of compiling switch statement if style and jump table.  

### If Style:
![[ifswitch_c_ex.png]]
The conditional jump determination is made by the comparison that occurs directly before each jump.

![[ifswitch_assembly_ex.png]]
These code sections are independent of each other because of the unconditional jumps to the end of the listing.





### Jump Table Style:
For larger contiguous switch statements. The compiler optimizes code to avoid making so many comparisons. 
#### Four Option Switch in C:
![[fourOption_switch_c.png]]
#### Four Option Switch Disassembly Graph:
![[fourOption_IFSTYLE_switch_disassembly_graph.png]]**(^IF style switch graph)**


In this example, ecx contains the switch variable, and 1 is subtracted from it in the first line. In the C code, the switch table range is 1 through 4, and the assembly code must adjust it to 0 through 3 so that the jump table can be properly indexed. The jump instruction at **1** is where the target is based on the jump table
![[fourOption_jumpTable_switch.png]]
**(^Jump Table switch statement)**
Jump table determines which of the four cases to choose. 
The four cases are each part of their own separate code chunk. 
Each of the four separate code chunks terminate with the same right box.


## Disassembling Arrays:
Arrays: In programming define ordered set of similar data items. 
Malware may use an array of pointers to strings containing multiple hostnames that represent options for connections.
![[array_c_ex.png]]
Note: array 'a' is locally defined. array 'b' is globally defined
![[array_assembly_ex.png]]
In assembly, arrays are accessed using a base address as a starting point. The size of each element is not always obvious, but it can be determined by seeing how the array is being indexed.

base address array 'b': dword_40A000
base address array 'a': var_14
both arrays are of type integer and each element is 4 bytes.
both arrays use ecx as the index and it is multiplied by four to account for each element. This new number is added to the base address to iterate through the array.

## Identifying Structs:
Structures (structs): are similar to arrays but comprise elements of different types. 
Malware may use structs to group information, this is easier than maintaining different variables independently. Especially if these variables must be accessed by many functions.
![[struct_c_ex.png]]
The structure above is made up of an integer array, a character, and a double. 
The struct 'gms' is defined as a global variable.
![[struct_assembly_ex.png]]
Structures are accessed with a base address (starting pointer). It is **difficult to determine whether nearby data types are part of the same struct or whether they just happen to be next to each other**. Depending on the structure’s context, your ability to identify a structure can have a significant impact on your ability to analyze malware.

struct 'gms' is a global variable with base address: dword_40EA30
base address of 'gms' is passed to test function (address sub_401000) via push eax (**1**)
![[struct_assembly_test_c.png]]
(^disassembly of test function)
arg_0 is the base address of the structure. 
Offset 0x14 stores the character within the struct, and 0x61 corresponds to the letter a in ASCII.
offset 0x18 is a double because it is used as part of a floating-point instruction (**1**)
integers are moved into offset 0, 4, 8, 0xC, and 0x10 by examining the for loop and where these offsets are accessed at (**2**). 
We can infer the contents of the structure from this analysis
## Analyzing Linked List Traversal
Linked List: data structure that consists of a sequence of data records. Each record includes a field that contains a reference to the next record in the sequence (link). Linked lists do not have to be stored contiguously and insertion and removal of nodes in a linked list can happen at any point.
![[linkedList_c_ex.png]]
The example above contains a linked list and its traversal. The linked list is made up of node structures named pnode. 
The first loop creates 10 nodes and fills them with data.
The second loop iterates through the records and prints their contents.

![[linkedList_assembly_ex.png]]
The best way to understand the disassembly is to identify the two code constructs within the main method.
In Listing 6-30, we identify the for loop first:
- var_C corresponds to i, which is the counter for the loop.
- var_8 corresponds to the head variable,
- var_4 is the curr variable -> var_4 is a pointer to a struct with two variables that are assigned values (**1, 2**)
The while loop (**3-5**) executes the iteration through the linked list. Within the loop, var_4 is set to the next record in the list at (**4**)

To recognize a linked list: recognize that some object contains a pointer that points to another object of the same type.
The recursive nature of the objects is what makes it linked
In this example, realize that at (**4**), var_4 is assigned eax, which comes from ```[eax+4]```, which itself came from a previous assignment of var_4. 
This means that whatever struct var_4 is must contain a pointer 4 bytes into it. This points to another struct that must also contain a pointer 4 bytes into another struct, and so on.