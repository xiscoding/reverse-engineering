#define _DEFAULT_SOURCE //to get DT_REG
#include <stdio.h>
#include <dirent.h> //for checking directories
int main() {
   int file_count_while = 0, file_count_for = 0;
   DIR *dir;
   struct dirent *entry;

   // Open the current working directory
   dir = opendir(".");
   if (dir == NULL) {
       perror("opendir");
       return 1;
   }

   // Count files using a while loop
   while ((entry = readdir(dir)) != NULL) {
       if (entry->d_type == DT_REG) {  // Check if it's a regular file
           file_count_while++;
       }
   }

   rewinddir(dir);  // Rewind the directory stream for the for loop

   // Count files using a for loop
   for (entry = readdir(dir); entry != NULL; entry = readdir(dir)) {
       if (entry->d_type == DT_REG) {
           file_count_for++;
       }
   }

   // Close the directory
   closedir(dir);

   printf("Number of files using while loop: %d\n", file_count_while);
   printf("Number of files using for loop: %d\n", file_count_for);

   return 0;
}