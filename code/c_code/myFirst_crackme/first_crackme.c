#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int validateSerialKey(const char *key) {
    int sum = 0;
    for (int i = 0; i < strlen(key); i++) {
        sum += key[i];
    }
    // The sum modulo 10 must equal 7
    return (sum % 10) == 7;
}



int main() {
    char userInput[256];

    printf("Enter the serial key: ");
    scanf("%255s", userInput);

    if (validateSerialKey(userInput)) {
        printf("Congratulations! You've solved the crackme.\n");
    } else {
        printf("Invalid serial key. Try again.\n");
    }

    return 0;
}
