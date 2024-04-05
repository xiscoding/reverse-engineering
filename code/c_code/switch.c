#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int main() {
    char input[100];
    int intVal;
    float floatVal;
    int type = 0; // 0 = not recognized, 1 = integer, 2 = float, 3 = string

    printf("Enter your input: ");
    fgets(input, 100, stdin); // Read input as string

    // Remove newline character if present
    input[strcspn(input, "\n")] = 0;

    // Try to parse input as integer and float
    if (sscanf(input, "%d", &intVal) == 1) {
        type = 1; // Input can be parsed as integer
    } else if (sscanf(input, "%f", &floatVal) == 1) {
        type = 2; // Input can be parsed as float
    } else {
        // Check if input is a string (assuming non-numeric input is considered a string)
        int isString = 1;
        for (int i = 0; i < strlen(input); i++) {
            if (!isprint(input[i])) {
                isString = 0;
                break;
            }
        }
        if (isString) {
            type = 3; // Input is a string
        }
    }

    // Use switch statement to determine the result based on type
    switch (type) {
        case 1:
            printf("Input is an integer\n");
            break;
        case 2:
            printf("Input is a float\n");
            break;
        case 3:
            printf("Input is a string\n");
            break;
        default:
            printf("The input is not recognized\n");
    }

    return 0;
}
