//
//	setket.c - program that sets a user's key into the kernel
//
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>



#define AES128_KEY_LEN		16	// in bytes

char inputKey[16];

int main(int argc, char *argv[]) 
{
    if(argc == 1)
    {
        unsigned int k0 = 0; 
        unsigned int k1 = 0;
        int status = syscall(564, k0, k1);
    }
    else if(argc == 2)
    {
        if (strlen(argv[1]) != AES128_KEY_LEN)
        {
            printf("The provided key is not 16 characters long!\n");
            return 1;
        }
        for (int index = 0; index < AES128_KEY_LEN; index++)
        {
            if (!isxdigit(argv[1][index]))
            {
                printf("There are non-hex characters in the provided key!\n");
                return 1;
            }
        }
        strcpy(inputKey, argv[1]);

        char first_half[9];
        char second_half[9];

        for(int index = 0; index < 8; index++)
            first_half[index] = inputKey[index];

        for(int index = 0; index < 8; index++)
            second_half[index] = inputKey[8 + index];

        first_half[8] = '\0';
        second_half[8] = '\0';

        unsigned int k0; 
        unsigned int k1; 

        k0 = (unsigned int)strtoul(first_half, NULL, 16);
        k1 = (unsigned int)strtoul(second_half, NULL, 16);

        // insert key for user
        int status = syscall(564, k0, k1);
    }
    return 0;
}
