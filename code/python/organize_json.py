#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 14 11:28:19 2024

@author: xdoestech
"""

import json
import glob
import os

def is_valid_record(record):
    """Checks if a record matches the required format."""
    return (isinstance(record, dict) and 
            'current_serial' in record and 
            'count' in record and 
            'result' in record)

def filter_and_save_data(data, base_filename):
    """Filters data and saves to multiple files if necessary."""
    valid_data = [record for record in data if is_valid_record(record)]
    chunk_size = 200000
    for i, chunk_start in enumerate(range(0, len(valid_data), chunk_size)):
        chunk = valid_data[chunk_start:chunk_start + chunk_size]
        with open(f"{base_filename}_{i+1}.json", "w") as f:
            json.dump(chunk, f, indent=4)  # Format for readability

def process_serial_files(directory=".", prefix="serial_state_"):
    """Main function to combine, filter, and split JSON files, grouping by num1."""
    all_files = glob.glob(os.path.join(directory, f"{prefix}*"))
    
    # Get unique num1 values from the filenames
    unique_prefixes = set(filename.split("_")[2] for filename in all_files)

    for num1 in unique_prefixes:
        # Filter files for the current num1 group
        filtered_files = [f for f in all_files if f.split("_")[2] == num1]

        all_data = []
        for filename in filtered_files:
            with open(filename, "r") as f:
                for line in f:  # Read line by line
                    try:
                        data = json.loads(line)  # Parse each line
                        all_data.append(data)
                    except json.JSONDecodeError as e:
                        print(f"Warning: Invalid JSON record in {filename}: {e}")


    # Determine the output filename base
    base_filename = f"serial_state_{all_data[0]['count']}" if all_data else "serial_state" 

    filter_and_save_data(all_data, base_filename)
