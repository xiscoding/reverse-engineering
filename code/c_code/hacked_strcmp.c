#define _GNU_SOURCE
/*
        ALWAYS RETURN 0 NO COMPARISON HAPPENS HAHA
        gcc -fPIC -shared -o hacked_strcmp.so hacked_strcmp.c

*/
#include <string.h>

int strcmp(const char *s1, const char *s2){

        return 0;
}

