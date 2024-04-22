#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
liba2k created this gist on Dec 21, 2021

xdoestech Modified on Fri Apr 19 19:10:30 2024

@author: liba2k
@author: xdoestech
"""

#!/usr/bin/env python3

import os
import sys
import click
import subprocess
import tempfile
import itertools as IT
import select
from time import sleep
import sys
print(sys.argv)

PROJECT_DIRECTORY = "/home/xdoestech/Desktop/reverse_engineering/code/ghidra_projects"
GHIDRA_PATH = "/home/xdoestech/Desktop/Ghidra/ghidra_11.0.2_PUBLIC_20240326/ghidra_11.0.2_PUBLIC"


def uniquify(path, sep = ''):
    """
    Generates a unique filename to avoid naming conflicts when creating files.
    It does this by temporarily modifying Python's default system for naming 
    temporary files.

    Parameters
    ----------
    path : (str)
        The original file path that needs to be made unique.
    sep : (str), optional
        Optional separator used in naming the unique file, 
        DEFAULT to an empty string. The default is ''.

    Yields
    ------
    TYPE
        DESCRIPTION.

    """
    def name_sequence():
        count = IT.count()
        yield ''
        while True:
            yield '{s}_{n:d}'.format(s = sep, n = next(count))
    orig = tempfile._name_sequence
    with tempfile._once_lock:
        tempfile._name_sequence = name_sequence()
        path = os.path.normpath(path)
        dirname, basename = os.path.split(path)
        filename, ext = os.path.splitext(basename)
        fd, filename = tempfile.mkstemp(dir = dirname, prefix = filename, suffix = ext)
        os.remove(filename)
        tempfile._name_sequence = orig
    return filename

def shouldRun():
    """
    Provides a brief window for users to cancel an operation. 
    If no key is pressed within 3 seconds, the script will continue.

    Returns
    -------
    bool
        Returns True if no key is pressed within 3 seconds, 
        indicating to proceed with execution.
        Returns False if a key is pressed within 3 seconds, 
        indicating to stop execution..

    """
    click.secho('Will run analysis in 3 seconds, press any key to cancel', fg='green')
    i, o, e = select.select( [sys.stdin], [], [], 3 )

    if (i):
        return False
    else:
        return True

@click.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('-t', '--temp', 'temp', is_flag=True)
def main(filename, temp):
    """
    Purpose:
        
        Manages the analysis of files using Ghidra based on user-provided parameters. 
        It checks the nature of the input (file or directory) and handles the 
        execution flow based on user confirmation to proceed.
    Parameters
    ----------
    filename : (str, required)
        The path to the file or directory that will be analyzed or used in the
        creation of a Ghidra project.
    temp : (bool)
        A flag that, when set, indicates that the Ghidra project file should be
        created in a temporary directory.

    Returns
    -------
    No direct output (return value), but this function triggers various actions
    such as printing to console, file analysis, 
    and execution of other programs.

    """
    if os.path.isdir(filename):
        return os.system(f'{GHIDRA_PATH}/ghidraRun')
    if '.gpr' in filename:
        os.system(f'{GHIDRA_PATH}/ghidraRun "{os.path.abspath(filename)}"')
        return
    if temp:
        proj_file = uniquify(os.path.join(PROJECT_DIRECTORY, os.path.basename(filename) + '.gpr'))
        out_dir = PROJECT_DIRECTORY
    else:
        proj_file = uniquify(filename + '.gpr')
        out_dir = os.path.dirname(filename)
        out_dir = out_dir if out_dir != '' else '.'
    proj_name = os.path.splitext(os.path.basename(proj_file))[0]
    file_output = subprocess.check_output(f'file "{filename}"', shell=True).decode('utf8')
    click.secho(file_output, fg='yellow')
    r = shouldRun()
    if r:
        os.system(f'{GHIDRA_PATH}/support/analyzeHeadless {out_dir} "{proj_name}" -import "{filename}"')
        os.system(f'{GHIDRA_PATH}/ghidraRun "{proj_file}"')

def process_file(filename, temp):
    """Process the given file using Ghidra with optional temp settings."""
    if os.path.isdir(filename):
        os.system(f'{GHIDRA_PATH}/ghidraRun')
        return
    if '.gpr' in filename:
        os.system(f'{GHIDRA_PATH}/ghidraRun "{os.path.abspath(filename)}"')
        return
    if temp:
        proj_file = uniquify(os.path.join(PROJECT_DIRECTORY, os.path.basename(filename) + '.gpr'))
        out_dir = PROJECT_DIRECTORY
    else:
        proj_file = uniquify(filename + '.gpr')
        out_dir = os.path.dirname(filename)
        out_dir = out_dir if out_dir != '' else '.'
    proj_name = os.path.splitext(os.path.basename(proj_file))[0]
    file_output = subprocess.check_output(f'file "{filename}"', shell=True).decode('utf8')
    click.secho(file_output, fg='yellow')
    if shouldRun():
        os.system(f'{GHIDRA_PATH}/support/analyzeHeadless {out_dir} "{proj_name}" -import "{filename}"')
        os.system(f'{GHIDRA_PATH}/ghidraRun "{proj_file}"')


if __name__ == '__main__':
    #!!!Check Command Syntax!!!: Make sure that the file path is enclosed in quotes when the script is run.
    if len(sys.argv) > 1:
        main()  # Called from the command line
    else:
        FILENAME = 'your_file_path_here'
        # Example direct call
        # Replace 'your_file_path_here' and 'temp_option' with your specific needs
        process_file(FILENAME, temp_option=True)