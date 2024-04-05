#include <time.h>
#include <stdio.h>


time_t current_time; // Global variable to store current time

int main() {
    struct tm *time_info;
    FILE *file_ptr;
    const char *message;
    // Get current time
    time(&current_time);
    time_info = localtime(&current_time);

    // Check time and open appropriate file
    if (time_info->tm_hour >= 0 && time_info->tm_hour < 6) {
        file_ptr = fopen("badtime.txt", "w");  // Open "badtime.txt" for writing
        message = "This is an inappropriate working hour\n"; // Local variable for message
        printf("%s", message);
    } else {
        file_ptr = fopen("goodtime.txt", "w"); // Open "goodtime.txt" for writing
        message = "This is an appropriate working hour\n"; // Local variable for message
        printf("%s", message);
    }

    if (file_ptr == NULL) {  // Check for file opening errors
        printf("Error opening file!\n");
        return 1;
    }

    // Write message to file
    fprintf(file_ptr, "This is %s\n", message);

    // Close the file
    fclose(file_ptr);

    return 0;
}