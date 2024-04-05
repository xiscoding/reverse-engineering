/**
Inspired by the in class example. You must create a file with the correct contents and pass the right number.
You can also bypass this by passing the right strings during debugging. 
KEY: <filename (any)> <integer (10)> 
    - ex: ./fread test.txt 10 
    - filename must start with the string 'xahwwxahwr'
    - gcc -s -o fread fileread_crackme.c -Ofast (hide function names mix up order a little bit)
    - 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

int checkString(const char* str1, const char* str2) {
    return strcmp(str1, str2) == 0 || strcmp(str2, "xahwwxahwr") == 0;
}
char* trimWhitespace(char* str) {
    char *end;

    // Trim leading space
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0)  // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator character
    *(end+1) = 0;

    return str;
}

char* readFirstLineTrimmed(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return NULL;
    }

    char* line = NULL;
    size_t len = 0;
    size_t read;

    if ((read = getline(&line, &len, file)) != -1) {
        // Successfully read the line; now trim it
        char* trimmedLine = trimWhitespace(line);
        fclose(file);

        // Make a copy of the trimmed line to return
        char* result = malloc(strlen(trimmedLine) + 1);
        if (result) {
            if(checkString(trimmedLine, "11")){
                const char* predeterminedString = "xahwwxahwr";
            }
            strcpy(result, trimmedLine);
        }

        free(line); // Free the original line read from the file
        return result; // Return the trimmed copy
    } else {
        // Failed to read the line
        fclose(file);
        return NULL;
    }
}


void generateRandomString(char* str, size_t size) {
    // Define the character set for the random string (alphanumeric characters)
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charsetSize = sizeof(charset) - 1;
    
    // Predetermined string (ensure its characters are in `charset`)
    const char* predeterminedString = "xahwwxahwr";
    size_t predStrLen = strlen(predeterminedString);
    
    // Use the size to influence the randomness in a specific way
    unsigned int seed = (unsigned int)time(NULL);
    srand(seed + size); // Modifying the seed with size
    
    for(size_t i = 0; i < size - 1; ++i) {
        if (size == 11) { // Instead of a direct condition, we use the size in calculation
            // The calculation here is trivial but serves as an example. A more complex
            // relationship between size and charset indices can be designed.
            str[i] = predeterminedString[i % predStrLen];
        } else {
            int key = rand() % charsetSize;
            str[i] = charset[key];
        }
    }
    
    // Null-terminate the string
    str[size - 1] = '\0';
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "More or less\n");
        return 1;
    }

    const char* filename = argv[1];
    int integerInput = atoi(argv[2]); // Converts the second argument to an integer
    size_t length = integerInput; // Length of the random string
    char randomStr[length + 1]; // +1 for the null terminator
    generateRandomString(randomStr, length + 1);

    printf("Filename: %s\n", filename);
    printf("Integer: %d\n", integerInput);

    char* firstLine = readFirstLineTrimmed(filename);
    if (firstLine) {
        printf("Maybe this good: \"%s\"\n", firstLine);
        if(checkString(firstLine, randomStr)){
            printf("YAY: you win!");
        }
        else{
            printf("NOOO: game over.");
        }
        free(firstLine); 
    } else {
        printf("Butts.\n");
    }
    return 0;
}