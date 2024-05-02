# reverse-engineering

## files and guides for understanding reverse engineering
Key files are listed below

### Static Analysis
* code/python/angr/view_file_info.py
    * Script that runs various terminal commands
    * **Functions that are NOT simple terminal commands**
        * decompile(): 
            * uses ghidrarecomp to create a directory of decompiled  C code from the binary file specified by user input default is None but set to (project_dir) in file
            * if output folder not specified saves folder to working directory
        * create_project_and_save_disassembled_code():
            * Creates project directory in current working directory 
    * Inputs/Variables to change:
        * FILENAME: path to file you want to analyze
        * create_project_and_save_disassembled_code(disassembled_code)
            * creates a new directory and saves disassembled_code there
            * new directory (project_dir) is used by decompile funciton to save decompilations
* code/python/angr/ghidra_manualAnalysis_prep.py
    * This script is used to prepare your system to run a ghidra project
    * Inputs/Variables to change:
        * PROJECT_DIRECTORY: directory that will be analyzed or used in the creation of a Ghidra project.
        * GHIDRA_PATH: path to ghidra installation
            * should be in ~/.bashrc file
            * SEE: code/python/angr/ghidra_setup_ubuntu.mkd
        * FILENAME: path to file you want to open in ghidra

### LLM Analysis
* code/python/langchain/langchain_autoAnal.py
    * uses chatGPT to provide a  summary of the code's functionality
    * Inputs/Variables to change:
        * DIRECTORY_PATH: path to directory containg decompiled code
        * DISASSEMBLED_FILE_PATH: path to disassembled file
        * OPENAI_API_TOKEN
        * QUERY: question you would like model to focus on during analysis
        * Limitations: only runs and queries model once, chain implementation needed
* There are three sections of this file where you can define a model: 
    * **Disassembled Analysis** 
        * Here we find that it is important to use the most powerful model available, this section analyzes the initial disassembled code you may have gotten from the view_file_info.py script. This section asks the selected llm to identify/determine the overall purpose of the code. We provide a sample prompt, but we recommend editing the ‘Example Responses’ Section of the code to have examples specific to the type of task you are expecting to analyze.  

    * **Function Selection**
        * Here we find that gpt3.5 offers comparable results to gpt4. This section asks the selected llm to identify functions of importance. We find that gpt3.5 is better at following instructions without adding its own ‘fluff’. This task is basic code exploration of a language that has existed for a long time. We find that gpt3.5 is sufficiently trained to perform this task and will follow the format more closely.  
        * We take these selected functions and find their decompiled equivalent (find_function_files). We suggest decompiling with ghidrarecomp using the decompile function available in view_file_info.py 

    * **Decompilation (c file) Analysis** 
        * As with the disassembled analysis, we find that gpt3.5 is not capable of providing an answer with the same quality as gpt4. 

### Angr Analysis
* code/python/angr/constraingSolver_basic.py
    * Given a simple program, finds a value that reaches the success_addr and avoids the fail_addr
    * Inputs/Variables to change:
        * BINARY_DIR: path to binary to analyze
        * success_addr (claripy.BVS): address to reach 
        * fail_addr (list): address(s) to avoid
    * Limitations: only works to find values
