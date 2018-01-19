/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 3: Problem 1, aes_image_encryption.c
//
//////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/////////////////////////////////////////////////////////////////////////
//	Encrypt an image file using AES CBC or AES ECB
// 	- Maintains first 54 bytes to keep format
//  - Does nothing with IV or salt so will not be able to decrypt properly
//	- For examining differences between CBC and ECB only
/////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[]) 
{
	char *key, *iv;
	char first_54[60];

	// Ensure the right number of variables have been passed
	printf("\n");
	if (argc < 4)
	{
		printf("Image Encryptor For Comparison Between AES CBC and ECB:\n");
		printf("\t- First argument is -cbc or -ecb for AES CBC or AES ECB.\n");
		printf("\t- Second argument is the image file you wish to encrypt.\n");
		printf("\t- Third argument is what you wish for the output name of the file\n");
		printf("\t- Fourth argument is the key you wish to encrypt with (optional but recommended).\n");
		printf("\t- Fifth argument is the iv you wish to encrypt with (optional but recommended, must also have a key).\n");
		printf("\n");
		return -1;
	}

	// First make sure the file exists
	int fd_image;
	if ((fd_image = open(argv[2], O_RDONLY)) == -1)
	{
		printf("Error: Could not open image file.\n");
		printf("\n");
		return -1;
	}

	// Save the first 54 bytes and close
	read(fd_image, first_54, 54);
	close(fd_image);

	// Get or declare the key
	// - Key can be entered as second argument when calling program
	if (argc < 5) 
	{
		key = "\"The key to cryptography!\"";
	}
	else
	{
		key = argv[4];
	}

	// Get or declare the iv
	if (argc < 6)
	{
		iv = "abfdacd12d34";
	}
	else
	{
		iv = argv[5];
	}

	// Check arguments and preform encryption/decryption
	char buff[512];
	if (strcmp(argv[1], "-cbc") == 0)
	{
		printf("Encrypting %s with CBC.", argv[3]);
		strcpy(buff, "openssl aes-256-cbc -in ");
		strcat(buff, argv[2]);
		strcat(buff, " -out ");
		strcat(buff, argv[3]);
		strcat(buff, " -k ");
		strcat(buff, key);
		strcat(buff, " -iv ");
		strcat(buff, iv);
		system(buff);
	}
	else if (strcmp(argv[1], "-ecb") == 0)
	{
		printf("Encrypting %s with ECB.", argv[3]);
		strcpy(buff, "openssl aes-256-ecb -in ");
		strcat(buff, argv[2]);
		strcat(buff, " -out ");
		strcat(buff, argv[3]);
		strcat(buff, " -k ");
		strcat(buff, key);
		strcat(buff, " -iv ");
		strcat(buff, iv);
		system(buff);
	}
	else
	{
		printf("Error: First argument must be either -cbc for AES CBC or -ecb for AES ECB.\n");
		printf("\n");
		return -1;
	}

	// Write the first 54 bytes back to the new file
	if ((fd_image = open(argv[3], O_WRONLY)) == -1)
	{
		printf("Error: Could not find output file.\n");
		printf("\n");
		return -1;
	}

	// Save the first 54 bytes
	write(fd_image, first_54, 54);

	// Close the file
	close(fd_image);

	printf("Done.\n");
	printf("\n");
	return 0;
}