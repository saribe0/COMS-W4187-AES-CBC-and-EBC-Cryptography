/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 3: Problem 4, sha1_password_crack.c
//
//////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>

/////////////////////////////////////////////////////////////////////////
//	Program that takes a dictionary of possible passwords and a SHA1 hashed
// 	- password in hex to try and crack the hex password. The dictionary must
//	- be a text file with one possible password per line. The SHA1 hash should
//	- be 20 bytes (160 bits). Optionally allows the use of salt which is used
// 	- added before the password is hashed (salt+password).
//
//	Using the password hashes and dictionary provided for the class, I got the 
//	- following for Hashes, Passwords, Salts
//	C604B40452110CA7B432EA2D51867F774EA4EB60, goldeneye
//	BD17A274120510B73CC32A41D1EDA0FC36ED458A, minemine, V0aFg83KN01xCFRosTJ5
//	73B64BE4D4F6D838DE43460C607805141875FF43, minemine, GhP49SwLN21VdeSsERt1
//	FA54A2C671B251D64060F2776072BF48590ABF2E, minemine, NQe0P3ts18bSuNdAe13v
//
/////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[]) 
{
	FILE * fp;
    char * password = NULL;
    size_t n = 0;
    int found = 0;
    char * password_buff;

	printf("\n");
	printf("Starting dictionary attack.\n");

	// Check for command line arguments
	if (argc < 3)
	{
		printf("SHA1 Password Cracker Using a Dictionary Attack.\n");
		printf(" - First argument is a text file with a list of possible passwords, one per line.\n");
		printf(" - Second argument is the hash trying to be cracked, 20 hex characters, no spaces.\n");
		printf(" - Third argument is the salt (optional).\n");
		return -1;
	}

	// Open the dictionary file
	if ((fp = fopen(argv[1], "r")) == NULL ) 
	{
		printf("Error: Could not open dictionary file. Please check your arguments.");
		return -1;
	}

	// Iterate through lines (possible passwords) in the file
    while (getline(&password, &n, fp) != -1) 
    {
    	// Get rid of new line in the string
    	password[strlen(password) - 2] = '\0';

    	// Add the salt if one is given
    	if (argc == 4)
    	{
	    	password_buff = malloc((strlen(password) + strlen(argv[3]) + 1) * sizeof(char));
	    	strcpy(password_buff, argv[3]);
	    	strcat(password_buff, password);
    	}
    	else
    	{
    		password_buff = malloc((strlen(password) + 1) * sizeof(char));
	    	strcpy(password_buff, password);
    	}

    	// Prepare hash destination
    	unsigned char hash[SHA_DIGEST_LENGTH];
		memset(hash, 0, sizeof(hash));

		// Hash the possible password
    	SHA1((unsigned char*) password_buff, strlen(password_buff), hash);

        // Convert the hash into hex
        char hash_hex[40];
        int jj = 0;
        for(int ii = 0; ii < SHA_DIGEST_LENGTH; ii++)
        {
        	sprintf(hash_hex + jj, "%02X", hash[ii]);
        	jj += 2;
        }

        // Check the input hash against the hashed password
        if (strcmp(hash_hex, argv[2]) == 0)
        {
        	printf("- Orignal password is: %s\n", password);
        	found = 1;
        	break;
        }

        if(password_buff) free(password_buff);
    }

    // If no matching password was found, inform the user
    if (found == 0)
    {
    	printf("- No passwords match the given hash.\n");
    }

    // Close the file and exit
    if(password) free(password);
    fclose(fp);	
    printf("\n");
    return 0;
}