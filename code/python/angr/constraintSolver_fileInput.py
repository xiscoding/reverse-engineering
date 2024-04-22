#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 31 13:27:40 2024

@author: xdoestech
"""

import angr
import claripy

def solve_crackme(binary_path, file_name, file_size):
    proj = angr.Project(binary_path, main_opts = {"base_addr": 0})

    # Create a symbolic buffer for the file contents
    file_content = claripy.BVS('file_content', file_size * 8)  # 8 bits per byte

    # Create a symbolic file and set its content
    sym_file = angr.storage.SimFile(file_name, content=file_content, size=file_size)

    # Initialize a state with the symbolic file, passing the filename and a symbolic integer as arguments
    integer_arg = claripy.BVS('integer_arg', 32)  # Assuming the integer argument is 32 bits
    state = proj.factory.entry_state(args=[binary_path, file_name, integer_arg], fs={file_name: sym_file})

    # Setup the simulation manager
    simgr = proj.factory.simulation_manager(state)

    # Find the state where the strcmp (or relevant comparison function) is called
    # Assuming 0x1518 is the address where the crucial comparison happens
    simgr.explore(find=0x1518)

    # Check if we found a successful state
    if simgr.found:
        found_state = simgr.found[0]
        # Retrieve the contents of the file that leads to success
        secret_key = found_state.solver.eval(file_content, cast_to=bytes)
        integer_solution = found_state.solver.eval(integer_arg, cast_to=int)
        return secret_key, integer_solution

    return None, None



binary_path = '/home/xdoestech/Desktop/reverse_engineering/code/c_code/myFirst_crackme/fread' 
file_name = 'test.txt'
file_size = 10  # You need to specify the expected size of the input, can be estimated or trial-error based

secret_content = solve_crackme(binary_path, file_name, file_size)
if secret_content:
    print(f"Found secret content: {secret_content}")
else:
    print("Failed to find the secret content.")
