//
//	protectfile.c - program that encrypts/decrypts a file
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

#include "aes.h"

//	debug definitions
//
//#define DEBUG_KEY		1
//#define DEBUG_CRYPT		1

//	useful macros
#define ctrace()		{printf("[%u]", __LINE__);}
#define getNibble(x)	(isdigit(x) ? x-'0': toupper(x)-'A'+10)

//	constant definitions
#define AES128_KEY_LEN		16	// in bytes
#define AES128_BLOCK_SIZE	16	// in bytes

// 	datatype definitions
union _CryptData {
	char bytes[16];
	struct {
		unsigned long i_number;
		unsigned long counter;	
	} cd;
};

typedef union _CryptData CryptData;

int isEncrypt = false, isDecrypt = false;
char inputKey[17];
struct stat sb;
char fileName[FILENAME_MAX];

int processArguments(int argc, char *argv[]);
char *transformInputKeyToAesKey(char *aesKey, char *inputKey);
char *xorBuffers( char *dest, char *bufA, char *bufB, unsigned length);
int cryptFile(char *fileName, char *aesKey);

int main(int argc, char *argv[]) 
{
	int status;

	if ((status = processArguments(argc, argv)) != 0)
		exit(status);

	// sb is already populated, make some sanity checks
	if (sb.st_mode & S_IFDIR)
	{
		printf("[Error] Can't operate on directories!\n");
		return 1;
	}

	mode_t on = sb.st_mode | S_ISVTX; // turn on the sticky bit
	status = chmod(fileName, on);
	if (status == 0 && isEncrypt) // sticky_bit is set, and we do -e
	{
		mode_t off = sb.st_mode & ~S_ISVTX; // turn off the sticky bit
		chmod(fileName, off);
		status = cryptFile(fileName, inputKey); // do encryption
		if (0 == status)
		{
			status = chmod(fileName, on);
			if (0 != status)
			{
				printf("[Error] chmod: %d\n", errno);
				status = errno;
			}
		}
	}
	else if (status == 0 && isDecrypt) // sticky_bit is set, and we do -e
	{
		mode_t off = sb.st_mode & ~S_ISVTX; // turn off the sticky bit
		chmod(fileName, off);
		status = cryptFile(fileName, inputKey); // do decryption
	}
	return status;
}

int cryptFile(char *fileName, char *aesKey)
{
	int fd=-1;
	int status = 0;
	off_t offset = 0;
	CryptData cd;
	char readBuffer[AES128_BLOCK_SIZE];
	char writeBuffer[AES128_BLOCK_SIZE];
	char cdEncrypted[AES128_BLOCK_SIZE];
	char iv[AES128_BLOCK_SIZE];
	size_t sizeRead = 0;
	size_t wroteSize = 0;
	bool firstPass = true;

	do
	{
		//	open file read+write mode with exclusive access
		fd = open(fileName, O_RDWR | O_EXCL);
		if (-1 == fd)
		{
			printf("[Error] File open error: %d\n", errno);
			status = errno;
			break;
		}

		if (0 != fstat(fd, &sb))
		{
			printf("[Error] File access error: %d\n", errno);
			status = errno;
			close(fd);
			break;
		}
		do
		{
			sizeRead = read(fd, readBuffer, AES128_BLOCK_SIZE);
			if (-1 == sizeRead)
			{
				printf("[Error] File read error: %d\n", errno);
				status = errno;
				break;
			}
			if (0 == sizeRead) 	//	reached end of file
			{
				break;
			}
			memset(&cd, 0, sizeof(cd));
			cd.cd.i_number = sb.st_ino;
			cd.cd.counter =  offset / AES128_BLOCK_SIZE; 

			if (0 == offset) // initialize init vector
				memset(&iv, 0, sizeof(iv));
			AES128_CBC_encrypt_buffer((uint8_t *)cdEncrypted, 
					(uint8_t *)cd.bytes, AES128_BLOCK_SIZE, 
					(uint8_t *)aesKey, (uint8_t *)iv);

			memcpy(iv, cdEncrypted, AES128_BLOCK_SIZE);

			//	seek back to where the data was read from
			if (offset != lseek(fd, offset, SEEK_SET))
			{
				printf("[Error] File seek error: %d\n", errno);
				status = errno;
				break;
			}

			xorBuffers(writeBuffer, cdEncrypted, readBuffer, AES128_BLOCK_SIZE);
			wroteSize = write(fd, writeBuffer, sizeRead);
			if (sizeRead != wroteSize)
			{
				printf("[Error] File write error: %d\n", errno);
				status = errno;
				break;
			}
			offset += AES128_BLOCK_SIZE;
		} while (true);
		close(fd);

	} while (false);

	return status;
}

//	XOR corresponding bytes in two buffers to destination
char *xorBuffers(char *destination, char *bufA, char *bufB, unsigned length)
{
	for (unsigned u=0; u<length;u++)
	{
		destination[u] = bufA[u] ^ bufB[u];
	}
	return destination;
}

// process command line arguments
int processArguments(int argc, char *argv[])
{
	// check number of arguments
	if (argc < 4)
	{
		printf("Command: protectfile [-e|-d] key fileName \n");
		return 1;
	}
	// check if we do encryption/decryption
	// set global 'encryptFlag' based on whether to encrypt or not
	if (strcmp(argv[1], "-e") == 0|| strcmp(argv[1], "--encrypt") == 0)
	{
		isEncrypt = true;
	} 
	else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--decrypt") == 0)
	{
		isDecrypt = true;
	}
	else
	{
		printf("[Error] Sorry, but (%s) option is unrecognized.\n", argv[1]);
		return 1;
	}

	// second argument is the AES128 key which is 16 char key = 16 bytes
	// 16 bytes is 32 hex characters, 1 byte = 8 bit, so 128 bit key
	if (strlen(argv[2]) != AES128_KEY_LEN)
	{
		printf("[Error] The provided key is not 16 characters long!\n");
		return 1;
	}
	for (int index = 0; index < AES128_KEY_LEN; index++)
	{
		if (!isxdigit(argv[2][index]))
		{
			printf("[Error] There are non-hex characters in the provided key!\n");
			return 1;
		}
	}
	//	copy key to 'inputKey'
	strcpy(inputKey, argv[2]);
	inputKey[16] = '\0';
	// third argument is the file
	if (0 != stat(argv[3], &sb))
	{
		printf("[Error: %d] when getting stat() of the file. \n", errno);
		return errno;
	}
	//	copy filename to 'fileName'
	strcpy(fileName, argv[3]);

	return 0;
}