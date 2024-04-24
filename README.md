# reverse-engineering

## files and guides for understanding reverse engineering
Key files are listed below

### Static Analysis
* code/python/angr/view_file_info.py
    * Script that runs various terminal commands
    * Inputs/Variables to change:
        * FILENAME: path to file you want to analyze
        * create_project_and_save_disassembled_code(disassembled_code)
            * creates a new directory and saves disassembled_code there
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

### Angr Analysis
* code/python/angr/constraingSolver_basic.py
    * Given a simple program, finds a value that reaches the success_addr and avoids the fail_addr
    * Inputs/Variables to change:
        * BINARY_DIR: path to binary to analyze
        * success_addr (claripy.BVS): address to reach 
        * fail_addr (list): address(s) to avoid
    * Limitations: only works to find values
