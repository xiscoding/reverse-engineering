#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 31 12:16:35 2024

@author: xdoestech
"""

import os
FILENAME = '/home/xdoestech/Desktop/reverse_engineering/code/c_code/myFirst_crackme/fread'

import subprocess

def get_file_info(filename):
    """
    Parameters
    ----------
    filename : string
        file to anlyze.
    Returns
    -------
    String
        string output.

    """
    if os.path.exists(filename) and os.access(filename, os.R_OK):
        return subprocess.run(['file', filename], capture_output=True, text=True).stdout.strip()
    else:
        return f"File {filename} not found or not accessible."
    

def get_strings(filename, min_length=4):
    """
    Parameters
    ----------
    filename : String
    min_length : INT, optional
        SMALLEST length string. The default is 4.
    Returns
    -------
    List
        list where each element is a string.
    """
    result = subprocess.run(['strings', '-n', str(min_length), filename], capture_output=True, text=True).stdout
    return result.splitlines()

def is_elf_file(file_info):
    """
    Check if the given file information indicates an ELF file.
    Parameters
    ----------
    file_info : str
        The output from get_file_info function.

    Returns
    -------
    bool
        True if the file is an ELF file, False otherwise.
    """
    return "ELF" in file_info

def readelf_analysis(filename):
    headers = subprocess.run(['readelf', '-h', filename], capture_output=True, text=True).stdout
    sections = subprocess.run(['readelf', '-s', filename], capture_output=True, text=True).stdout
    return headers, sections

def view_hexdump(filename):
    return subprocess.run(['xxd', filename], capture_output=True, text=True).stdout

def edit_hex(filename, address, hex_data):
    # Example: echo "0000000: 4142" | xxd -r - unknown2.bin
    echo_process = subprocess.Popen(['echo', f"{address}: {hex_data}"], stdout=subprocess.PIPE)
    subprocess.run(['xxd', '-r', '-', filename], stdin=echo_process.stdout)
    
def disassemble(filename, mode='intel'):
    disassembled = subprocess.run(['objdump', '-M', mode, '-d', filename], capture_output=True, text=True).stdout
    hexdump = subprocess.run(['objdump', '-s', filename], capture_output=True, text=True).stdout
    #objdump -drwC -Mintel --visualize-jumps=color https://stackoverflow.com/questions/74793599/better-way-than-a-terminalobjdump-to-read-assembly
    return disassembled, hexdump

def decompile(filename, output_dir=None):
    #https://reverseengineering.stackexchange.com/questions/21207/use-ghidra-decompiler-with-command-line
    #https://reverseengineering.stackexchange.com/questions/21630/ghidra-how-to-run-a-python-3-script-with-headless-analyzer/21632#21632
    #https://github.com/clearbluejar/ghidrecomp
  """
  Decompiles all functions in a binary using ghidrecomp.
  Args:
      filename: Path to the binary file to decompile.
      mode: Decompilation mode (e.g., "high", "medium", "low").
      output_dir: Directory to store the decompiled functions.
          IF none specified ghidrecomps folder is created in working directory
  """
  if output_dir is None:
      # Build the ghidrecomp command
      output_dir = 'ghidrecomps'
      command = ["ghidrecomp", filename]
  else:
      command = ["ghidrecomp", "-o", output_dir, filename]
  # Execute the command using subprocess.run
  subprocess.run(command, check=True)
  # Handle potential errors (raised by check=True)
  print(f"Decompiled functions written to: {output_dir}")

def trace_with_gdb(binary_path):
    gdb_commands = """
    set logging enabled on
    break main
    run
    continue
    quit
    """
    with open("gdb_commands.gdb", "w") as file:
        file.write(gdb_commands)
    result = subprocess.run(['gdb', '--batch', '-x', 'gdb_commands.gdb', binary_path], capture_output=True, text=True)
    return result.stdout

strings = get_strings(FILENAME)
file_info = get_file_info(FILENAME)
if is_elf_file(file_info):
    print(f"{FILENAME} is an ELF file.")
    file_header, sym_table = readelf_analysis(FILENAME)
    disassembled, hexdump = disassemble(FILENAME)
else:
    print(f"{FILENAME} is not an ELF file.")
decompile(FILENAME)








































