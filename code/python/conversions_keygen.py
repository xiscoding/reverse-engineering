from keys import *
def string_to_keygen(charAr):
    """Returns the sum of integer ASCII values of characters"""
    return sum(char_to_decimal_ascii(char) for char in charAr)  # Filter non-ASCII characters

def char_to_decimal_ascii(char):
    """Returns the ASCII value of char."""
    if ord(char) > 127 or ord(char) < 32:
        raise ValueError(f"Character '{char}' is not ASCII")
    return ord(char)
def char_to_hex(char):
    """Returns the hex representation of the ASCII value of char."""
    return hex(char_to_decimal_ascii(char))

def decimal_to_char(num):
    """Returns the ASCII character corresponding to decimal value num."""
    if not 0 <= num <= 127:
        raise ValueError(f"Decimal value {num} is not in ASCII range")
    return chr(num)
def decimal_to_hexNum(num):
    """Converts a decimal number to 8-bit hex numbers"""
    # hex_str = format(num, '04x')  # Convert to 4-digit hex string with leading zeros
    # grouped_hex = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))  # Group into pairs
    return hex(num)
def decimal_to_hexStr(num):
    """Converts a decimal number to 16-bit hex numbers, formatted as two-character hex pairs."""
    hex_str = format(num, '04x')
def decimalList_to_string_ascii(decList):
    """Returns an ascii string given a list of decimal values
    INPUT: [116, 101, 115, 116]
    OUPTUT: 'test'
    """
    string = ''.join(decimal_to_char(dec) for dec in decList)
    return string

def hex_to_string(hexStr):
    """Returns the ASCII string corresponding to hex string hexStr."""
    return ''.join(hex_to_char(hexStr[i:i+2]) for i in range(0, len(hexStr), 2))
def hex_to_char(hexStr):
    """Returns the ASCII character corresponding to hex string hexStr."""
    num = int(hexStr, 16)
    return decimal_to_char(num)
def hex_to_char_array(dword):
    """
    Converts a hexadecimal string into an array of characters.
    Args:
    dword: A hexadecimal string, e.g., output of format(num, '04x').
    Returns:
    A list of characters representing the hexadecimal string.
    """
    # Directly convert the hexadecimal string to a list of characters
    char_array = [char for char in dword]
    return char_array

def calculate_target_sum(hex_array):
    """
    Calculates the target sum of an array containing hexadecimal digits from 0x0 to 0xf.

    Args:
    hex_array: An array of integers, where each integer is a hexadecimal digit (0-15).

    Returns:
    The sum of the hexadecimal digits in the array.
    """
    # Sum the values in the array directly
    target_sum = sum(hex_array)

    return target_sum

def hex_to_decimal(hex_str):
    """Converts a hex string to its decimal equivalent.
    INPUT: '0x74
    OUTPUT: 116
    """
    return int(hex_str, 16)

def string_to_decimalList_ascii(string):
    """Returns a list of ASCII values of characters in string."""
    return [char_to_decimal_ascii(char) for char in string]

def string_to_hexList(string):
   """ Return list of hex values coressponding to each character in input string"""
   return [char_to_hex(char) for char in string]


def input_to_index(input):
    """Converts an integer to an integer between 0 and 31 using modulo and direct string conversion."""
    modulo_result = input % 496
    hex_str = format(modulo_result, 'x')  # Convert to hex string
    return int(hex_str, 16)  # Convert hex string to integer

def swap_char(index, s):
    """Swaps the character at the given index with its calculated counterpart.
    Args:
        index: The index of the character to swap.
        s: The string to modify.
    Returns:
        The modified string with swapped characters.
    """
    # Ensure the index is within the bounds of the string
    if index >= len(s) or index < 0:
        raise ValueError("Index is out of the string's bounds.")
    # Convert the string to a list of ASCII decimal values
    decList = string_to_decimalList_ascii(s)
    # Calculate the swap index
    swap_index = (index + len(s)) % (len(s) // (index + 1))
    # Ensure the swap index is within bounds
    swap_index = swap_index % len(s)
    # Perform the swap
    decList[index], decList[swap_index] = decList[swap_index], decList[index]
    # Convert the modified decimal list back to a string
    return decimalList_to_string_ascii(decList)

def create_unique_keygen(num, s):
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
      return beta_key  # Return the generated keygen if it matches
    else:
      print(f"swap_char() FAILED. beta_key: {beta_key} len: {len(swap_0)} TRUE_VALUE: {string_to_keygen(TRUE_VALUE)} len {len(TRUE_VALUE)}")
      nextNum = num % len(TRUE_VALUE)
      return create_unique_keygen(num, swap_char(nextNum, TRUE_VALUE))  # Return the True Value otherwise

def find_valid_byte(dword):
    """Finds a 4-byte hex with the same digit sum as the input within given bounds.
    Args:
        dword: The input 4-byte hex string.
    Returns:
        A new 4-byte hex string with the same digit sum, within bounds.
    """
    # Convert hex string to list of integers (hex digits)
    hex_digits = [int(char, 16) for char in dword]
    # Calculate the sum of the hex digits
    digit_sum = sum(hex_digits)
    # Find a valid pair of digits within bounds that sum to the same value
    for i in range(0x20, 0x7F):  # Use 0x7F instead of 0x7E + 0x1 for inclusive range
      for j in range(0x20, 0x7F):
        if i + j == digit_sum:
          new_hex = f"{i:02X}{j:02X}"  # Format into 4-byte hex string
          return new_hex
    # If no valid pair is found, return the original value
    return dword


def uwu_to_string(num):
    """Returns the ASCII string representing num using a base ASCII value.
    num // 32  gives the number of characters needed and modulo by 32 provides the character index.
    
    """
    result = ''
    base_char_value = 32  # Ensure ASCII base value
    while num > 0:
        if num - base_char_value >= 0:
            result += decimal_to_char(base_char_value)
            num -= base_char_value
        else:
            base_char_value = num  # Adjust base value if needed
    return result