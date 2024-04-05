# 1. Import necessary libraries
import angr
import logging

# 2. Configure logging (optional)
logging.getLogger('angr').setLevel(logging.DEBUG)  # Adjust logging level as needed

# 3. Load the binary file with appropriate backend
binary_path = '/home/xdoestech/Desktop/reverse_engineering/myFirst_crackme/first_crack'
project = angr.Project(binary_path, auto_load_libs=False)  # Adjust backend if necessary

# 4. Analyze function calls
cfg = project.analyses.CFGFast()  # Control Flow Graph analysis

# 5. Output function calls in a user-friendly format
print("Function Calls:")
for function_addr in cfg.kb.functions.keys():
    function_name = cfg.kb.functions[function_addr].name
    if function_name is None:
        function_name = "Unnamed Function at 0x%x" % function_addr
    print("-", function_name)
print(cfg.kb.functions.keys())

