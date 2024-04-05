# Given Password String: "HBjPCJzwabHkAHsBzlfYhmzEUPpahdL"
# TRUE VALUE: "wzJCPjBHBsHAkHbazmhYdflzLdhapPUE"
"""
swap_char(): creates the new string
create_unique_keygen(): double checks the new string is valid and returns the new string and uwu value
main(): prints the new key last
"""
import random


TRUE_VALUE= "wzJCPjBHBsHAkHbazmhYdflzLdhapPUE"
TRUE_KEYGEN= 2977
password_string = "HBjPCJzwabHkAHsBzlfdYhmzEUPpahdL"

def char_to_decimal_ascii(char):
    """Returns the ASCII value of char."""
    if ord(char) > 127 or ord(char) < 32:
        raise ValueError(f"Character '{char}' is not ASCII")
    return ord(char)

def string_to_keygen(charAr):
    """Returns the sum of integer ASCII values of characters"""
    return sum(char_to_decimal_ascii(char) for char in charAr)  # Filter non-ASCII characters

def string_to_decimalList_ascii(string):
    """Returns a list of ASCII values of characters in string."""
    return [char_to_decimal_ascii(char) for char in string]

def decimal_to_char(num):
    """Returns the ASCII character corresponding to decimal value num."""
    if not 0 <= num <= 127:
        raise ValueError(f"Decimal value {num} is not in ASCII range")
    return chr(num)

def decimalList_to_string_ascii(decList):
    """Returns an ascii string given a list of decimal values
    INPUT: [116, 101, 115, 116]
    OUPTUT: 'test'
    """
    string = ''.join(decimal_to_char(dec) for dec in decList)
    return string

def swap_char(index=420, s=password_string):
    """Swaps the character at the given index with a randomly chosen character.   
    Args:
        index: The index of the character to swap.
        s: The string to modify.       
    Returns:
        The modified string with swapped characters.
    """
    # Ensure the index is within the bounds of the string
    if index >= len(s) or index < 0:
        index = index % len(s)    
    # Convert the string to a list of ASCII decimal values
    decList = string_to_decimalList_ascii(s)    
    # Choose a random index to swap with, ensuring it's different from the input index
    swap_index = index
    while swap_index == index:
        swap_index = random.randint(0, len(s) - 1)    
    # Perform the swap
    decList[index], decList[swap_index] = decList[swap_index], decList[index]
    # Convert the modified decimal list back to a string
    return decimalList_to_string_ascii(decList)

def create_unique_keygen(num=69, s=password_string):
    """Creates a unique keygen by swapping characters and checking against a True Value.
    Args: STRING
        num: The index of the character to swap.
        s: The string to modify.
    Returns: STRING
        The generated keygen (either the modified string or the True Value).
    """
    swap_0 = swap_char(num, s)  # Modify string using swap_char
    beta_key = string_to_keygen(swap_0) # generate keygen
    # Check if the generated keygen matches the True Value
    if beta_key == TRUE_KEYGEN:
      return beta_key, swap_0  # Return the generated keygen if it matches
    else:
      print(f"swap_char() FAILED. beta_key: {beta_key} len: {len(swap_0)} TRUE_VALUE: {string_to_keygen(TRUE_VALUE)} len {len(TRUE_VALUE)}")
      nextNum = num % len(TRUE_VALUE)
      return create_unique_keygen(num, swap_char(nextNum, TRUE_VALUE))  # Return the True Value otherwise
    
import sys
import subprocess

def main():
    # Prompt user for input
    num = int(input("Enter a number: "))
    file_path = input("Enter the file path: ")
    
    # Create a unique keygen based on user input
    _, new_string = create_unique_keygen(num, password_string)
    
    # Normally, here you'd pass `new_string` as input to the command at `file_path`
    # For security reasons, we will not execute commands, but show what would be executed
    print(f"Command to be executed: {file_path} {new_string}")
    print(f"New key: {new_string}")
    # Example of safely calling an external command, commented out for safety
    # subprocess.run([file_path, new_string], check=True)

if __name__ == "__main__":
    main()
