/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 3: Problem 3, ecb_detection.c
//
//////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/////////////////////////////////////////////////////////////////////////
//	Encode is a program that uses the openssl command line commands
// 	- to encode an input using AES CBC or ECB. Which method it chooses
// 	- is decided randomly. It is up to the main function to decide which
//	- one it is using. Keys and IVs are also random. The input will not
//	- be able to be decoded. The point is to try and determine the encryption
//	- method that is randomly chosen.
//
//	* Random numbers must be seeded in your own code first (srand(time(NULL)))
/////////////////////////////////////////////////////////////////////////

// Must be checked by hand for acuracy - otherwise would defeat the purpose of the detect
// - as the encryption type would have to be returned by the encode function.
#define ITERATIONS 5


int encode(char* const in, char** const out, const int in_length, int* const out_len)
{
	int blocks, tmp_unencrypted, tmp_encrypted;
	char key[18], iv[18];
	char name_buff_in[32];
	char name_buff_out[32];

	// Get the length of the output string
	// - 64 bytes/block. The output length is always padded -> When even number of
	// - blocks, there is one full block of padding. Otherwise, the input is padded
	// - up to the next full block. 
	blocks = 64 / in_length;
	*out_len = (blocks + 1) * 16;

	// Open a temporary file and write the input to it
	// - Creates the file name buffer and file
	// - Writes to the file so the file has the proper input
	// - Closes the file so it can be opened by AES - maintain file descriptor so exists until unlink
	memset(name_buff_in, 0, sizeof(name_buff_in));
	strncpy(name_buff_in, "ecb_encode_in-XXXXXX", 28);
	if ((tmp_unencrypted = mkstemp(name_buff_in)) == -1) return -1;
	if (write(tmp_unencrypted, in, in_length) == -1) return -1;
	if (close(tmp_unencrypted) == -1) return -1;


	// Open a temp file for the output to be written to by the program
	// - Creates the file name buffer and file
	// - Closes the file so it can be opened by AES - maintain file descriptor so exists until unlink
	memset(name_buff_out, 0, sizeof(name_buff_out));
	strncpy(name_buff_out, "ecb_encode_out-XXXXXX", 29);
	if ((tmp_encrypted = mkstemp(name_buff_out)) == -1) return -1;

	// Randomly generate 16 character key (and IV in case of CBC)
	// - Only use alpha-numeric so for ease, use array access instead of character casting
	int ii;
	char* vals_norm = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	char* vals_hex = "abcdef0123456789";
	for(ii = 0; ii < 16; ii++)
	{
		key[ii] = vals_norm[rand() % 62];
		iv[ii] = vals_hex[rand() % 16];
	}
	key[16] = '\0';
	iv[16] = '\0';


	// Randomly decide whether to use ECB or CBC
	// - Done this way because when using %2, did not seem that random due to seeding
	if (rand() % 1000 > 500)
	{
		// ECB was chosen
		printf("Encrypting input using ECB.\n");

		// Create commmand and execute it
		char buff[512];
		strcpy(buff, "openssl aes-256-ecb -in ");
		strcat(buff, name_buff_in);
		strcat(buff, " -out ");
		strcat(buff, name_buff_out);
		strcat(buff, " -k ");
		strcat(buff, key);
		strcat(buff, " -iv ");
		strcat(buff, iv);
		strcat(buff, " -nosalt");
		system(buff);
	}
	else
	{
		// CBC was chosen
		printf("Encrypting input using CBC.\n");

		// Create commmand and execute it
		char buff[512];
		strcpy(buff, "openssl aes-256-cbc -in ");
		strcat(buff, name_buff_in);
		strcat(buff, " -out ");
		strcat(buff, name_buff_out);
		strcat(buff, " -k ");
		strcat(buff, key);
		strcat(buff, " -iv ");
		strcat(buff, iv);
		strcat(buff, " -nosalt");
		system(buff);
	}

	// Read from the temporary file into the output buffer
	*out = malloc(sizeof(char) * *out_len);
	memset(*out, 0, sizeof(**out));
	if(read(tmp_encrypted, *out, *out_len) != *out_len) return -1;

	// Close the temporary files by closing the encryped one and unlinking both
	if (close(tmp_encrypted) == -1) return -1;
	if (unlink(name_buff_in) == -1) return -1;
	if (unlink(name_buff_out) == -1) return -1;

	return 0;
}


int main(int argc, char *argv[]) 
{
	printf("\n");
	printf("Running multiple iterations of encode and detecting whether ECB or CBC was used.\n\n");

	// For since ECB always encodes identical plaintext blocks into identical ciphertexts
	// - we can use a string that is twice the block size and repeats itself. The ciphertext
	// - should be identical for both halves, just like the plaintext input. AES always 
	// - encodesin 16 byte (128 bit) blocks and each character is one byte in C. Therefore
	// - we use a 32 character string whose second half is the same as its first half.
	char* input_string = "_32__characters__32__characters_";
	int output_len;
	char* output;

	// Seed the random number generator
	srand((unsigned) time(NULL));

	int ii;
	for(ii = 0; ii < ITERATIONS; ii++)
	{
		// Get the encrypted result
		if (encode(input_string, &output, strlen(input_string), &output_len) == -1) return -1;

		// Compare the result - if both halves of the string are equal, its ecb, else cbc
		// - Because the output length has one extra block of padding, only iterate through
		// - the first two blocks (16 bytes). This is because an even number of blocks was 
		// - used as the input.
		int jj, cbc = 0;
		for(jj = 0; jj < 16 ; jj++)
		{
			if(output[jj] != output[jj+16])
				cbc = 1;
		}

		// Declare result
		if (cbc == 1)
			printf("- Input was encrpted with: CBC.\n\n");
		else
			printf("- Input was encrpted with: ECB.\n\n");
	}

	return 0;
}