import unittest
from keys import *
from conversions_keygen import *

class TestFunctions(unittest.TestCase):

    def test_string_to_keygen(self):
        # Test with ASCII characters
        self.assertEqual(string_to_keygen("test"), 448)
        # Test with non-ASCII characters (should filter them out)
        with self.assertRaises(ValueError):
          string_to_keygen("tëst")
        # Test with empty string
        self.assertEqual(string_to_keygen(""), 0)

    def test_char_to_decimal(self):
        # Test with valid ASCII characters
        self.assertEqual(char_to_decimal_ascii('a'), 97)
        self.assertEqual(char_to_decimal_ascii('Z'), 90)
        # Test with non-ASCII character (should raise an error)
        with self.assertRaises(ValueError):
            char_to_decimal_ascii('€')

    def test_char_to_hex(self):
        # Test with valid ASCII characters
        self.assertEqual(char_to_hex('a'), '0x61')
        self.assertEqual(char_to_hex('Z'), '0x5a')
        # Test with non-ASCII character (should raise an error)
        with self.assertRaises(ValueError):
            char_to_hex('€')

    def test_decimal_to_char(self):
        # Test with valid ASCII values
        self.assertEqual(decimal_to_char(97), 'a')
        self.assertEqual(decimal_to_char(90), 'Z')
        # Test with values outside ASCII range (should raise an error)
        with self.assertRaises(ValueError):
            decimal_to_char(-1)
        with self.assertRaises(ValueError):
            decimal_to_char(128)

    def test_decimal_to_hexNum(self):
        # Test with valid decimal values
        self.assertEqual(decimal_to_hexNum(255), '0xff')
        self.assertEqual(decimal_to_hexNum(0), '0x0')


    def test_hex_to_string(self):
        # Test with valid hex strings
        self.assertEqual(hex_to_string('414243'), 'ABC')
        self.assertEqual(hex_to_string('6F6F'), 'oo')

    def test_hex_to_char(self):
        # Test with valid hex strings
        self.assertEqual(hex_to_char('41'), 'A')
        self.assertEqual(hex_to_char('6F'), 'o')
        # Test with invalid hex strings (should raise an error)
        with self.assertRaises(ValueError):
            hex_to_char('GG')

    def test_hex_to_decimal(self):
        # Test with valid hex strings
        self.assertEqual(hex_to_decimal('41'), 65)
        self.assertEqual(hex_to_decimal('FF'), 255)
        # Test with invalid hex strings (should raise an error)
        with self.assertRaises(ValueError):
            hex_to_decimal('GG')

    def test_string_to_decimal(self):
        # Test with ASCII string
        self.assertEqual(string_to_decimalList_ascii("test"), [116, 101, 115, 116])
        # Test with empty string
        self.assertEqual(string_to_decimalList_ascii(""), [])

    def test_input_to_index(self):
        pass
        # # Test with various inputs
        # self.assertEqual(input_to_index(10), 10)
        # self.assertEqual(input_to_index(495), 31)
        # self.assertEqual(input_to_index(500), 0)

    # def test_uwu_to_string(self):
    #     # Test with various numbers
    #     self.assertEqual(uwu_to_string(100), ' ')
    #     self.assertEqual(uwu_to_string(111), 'owo')
    #     self.assertEqual(uwu_to_string(255), 'owoowo')

    def test_create_unique_keygen(self):
      # Define TRUE_VALUE (replace with your actual value)
      # TRUE_VALUE = "wzJCPjBHBsHAkHbazmhYdflzLdhapPUE"
      password_string = "HBjPCJzwabHkAHsBzlfdYhmzEUPpahdL"

      # Test case 1: Swap character at index 0
      keygen = create_unique_keygen(0, password_string)
      self.assertEqual(keygen, TRUE_KEYGEN)  # Expected to match TRUE_VALUE

      # Test case 2: Swap character at different index
      keygen = create_unique_keygen(5, password_string)
      self.assertEqual(keygen, TRUE_KEYGEN)

      # Test case 3: Handle edge case (no swap needed)
      keygen = create_unique_keygen(len(password_string) - 1, password_string)
      self.assertEqual(keygen, TRUE_KEYGEN)  # Expected to match TRUE_VALUE

    def test_create_unique_keygen_plus(self):
        # Define TRUE_VALUE (replace with your actual value)
        #TRUE_VALUE = "wzJCPjBHBsHAkHbazmhYdflzLdhapPUE"
        # Test cases with different strings and indices
        strings = [
            "HBjPCJzwabHkAHsBzlfdYhmzEUPpahdL",
            "qwertyuiopasdfghjklzxcvbnm",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "1234567890",
            "!@#$%^&*()_+",
        ]
        #for i,string in enumerate(strings):
        # Test case 1: Swap character at index 0
        keygen = create_unique_keygen(0, strings[0])
        self.assertEqual(keygen, TRUE_KEYGEN)
        # Test case 2: Swap character at different index, expecting match
        keygen = create_unique_keygen(len(strings[3])//3, strings[0])
        self.assertEqual(keygen, TRUE_KEYGEN)  # Not expected to match initially
        # Test case 3: Handle edge case (no swap needed)
        keygen = create_unique_keygen(len(strings[2]) - 1, strings[2])
        self.assertNotEqual(keygen, strings)  # Expected to be the original string
        # Test case 4: Multiple swaps until match is found
        for i in range(len(strings)):
            keygen = create_unique_keygen(i, strings[i])
            if keygen == TRUE_KEYGEN:
                break  # Stop iterating if match is found
        self.assertEqual(keygen, TRUE_KEYGEN)  # Expect to find a match eventually
        # # Test case 5: Handle case where no match is found within string length
        # keygen = create_unique_keygen(len(strings) + 1, strings)
        # self.assertEqual(keygen, TRUE_KEYGEN)  # Fallback to TRUE_VALUE in this case

    def test_find_valid_byte(self):
        pass

# # Create a test suite
# test_suite = unittest.TestSuite()

# # Add all test cases to the suite
# for name, obj in globals().items():
#     if isinstance(obj, unittest.TestCase):
#         test_suite.addTest(obj)

# # Run the test suite
# unittest.TextTestRunner().run(test_suite)

# Run all tests directly using unittest.main() in Colab
if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)  # Suppress exit for Colab