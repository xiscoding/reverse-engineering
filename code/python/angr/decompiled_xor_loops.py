#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May  5 23:13:43 2024

@author: xdoestech
"""

def process_serial(serial):
    eax = 0
    ecx = 6
    ebx = 0
    final_dl = 0
    while ebx < len(serial):
        dl = serial[ebx]  # Load byte from the serial array at index ebx
        #print(f"dl: {dl}")
        eax = (eax * ecx) & 0xFFFFFFFF  # Multiply eax by 6 and truncate to 32 bits
        eax = (eax + dl) & 0xFFFFFFFF  # Add the current byte value to eax and truncate to 32 bits
        ebx += 1  # Move to the next byte
        print(f"eax: {eax}")
        # If the current byte (dl) is zero, break out of the loop
        if dl == 0:
            break
        final_dl = dl
    return eax - final_dl

# Example usage
edx = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31]  # Example data
result = process_serial(edx)
print(f"Result of process_serial: {result:#x}")

def unscramble_data(eax, serial):
    ebx = 0xd  # constant value as per request
    edx = 0  # Initially zero

    # Assume mapping of serial to memory values like in the C function
    eax ^= int.from_bytes(serial[8:12], 'little')  # DWORD at mem_40304e
    eax ^= int.from_bytes(serial[6:8], 'little')  # WORD at mem_40304d
    eax ^= int.from_bytes(serial[2:6], 'little')  # DWORD at mem_40304c
    eax ^= serial[0]  # BYTE at mem_40304a

    eax ^= edx  # XOR eax with edx (no effect)
    eax ^= ebx  # Finally, XOR with ebx

    return eax

# Example usage
serial = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31]  # Example data
initial_eax = 0xc2d5be06 #0xcd15ac92 #0xcd159d9f  # Initial eax value for testing
result_eax = unscramble_data(initial_eax, serial)
print(f"Result of unscramble_data: {result_eax:#x}")

def find_edx_array(desired_result):
    edx = []
    eax = desired_result
    while eax > 0:
        remainder = eax % 6
        eax //= 6  # Integer division to undo left shift
        edx.append(hex(remainder))  # Convert remainder to hex string without 0x prefix
    edx.reverse()  # Reverse the order for correct byte placement
    return edx

# Example usage
desired_result = 0x12345678
edx_array = find_edx_array(desired_result)
print(f"edx array for desired result: {edx_array}")
