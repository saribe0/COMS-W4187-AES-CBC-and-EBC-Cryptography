# COMS-W4187-AES-CBC-and-EBC-Cryptography-and-SHA1
COMS W4187 Security Architecture and Engineering HW3: AES CBC and EBC Cryptography and SHA1

## Problem 1
In this problem, we look at the difference in security between AES ECB and AES CBC. To do this, we develop a program to encrypt an image using both formats (leaving the 54 first bytes so it can be opened as an image still). For my implementation, I developed a program that takes in 5 command line arguments and outputs the encrypted file. The arguments to the program are:

- Argument 1: -cbc or -ecb. This option indicates to theprogram which type of AES encryption to use.
- Argument 2: The path of the image file you wish to encrypt.
- Argument 3: The file name you would like for the output image file.
- Argument 4: The key you wish to encrypt the file with. This argument is optional. If none is given, the key will be: "The key to cryptography!"
- Argument 5: The IV you wish to encrpyt the file with. This argument is also optional and requires you provide a key as well. It is possible to give a key and no IV, however you can not give an IV and no key. If no IV is given, the default is: "abfdacd12d34"

For my implementation, I first process the command line arguments then save the first 54 bytes of the image. Then I create the openssl command and use system() to call the openssl command as its more convenient than interfacing with the AES c library. After outputting the encrypted image, I open it and copy the saved 54 header bytes back to the header so it can be opened as an image. The C file can be created with the provided Makefile. Two examples of using the program to create both an ECB and CBC encrypted image are:

```
./aes_image_encryption -cbc sample_img.bmp sample_CBC.bmp
./aes_image_encryption -ecb sample_img.bmp sample_ECB.bmp
```

The image is still visible in the ECB encryption because the block cipher is only per block. There is no connection between the blocks so any underlying image biases are also biased in the encrypted version. The CBC version is almsot completely random and the image is completely undecernable because the block encryptions are chained together so that even if two blocks are the same, the output isn't the same. Each blocks encrpytion is dependent on the other blocks and thus the whole file becomes completely masked.

Code and encrypted images are found in ./Problem 1 - CBC vc ECB.

## Problem 2
In problem 2 we are given the plaintext "you fail to plan,  which means, you plan to fail" and its ciphertext "16fe5ba9e7d12e9a45b32ee1c49130c40cd2bb9592493f8c1b38323f752786e7617ed108bdc07 e21d75e8f0c8a6f2c2e" encoded in ECB-256 and some unknown secret key. The objective is to obtain the cipher text for "you plan to fail,  which means, you fail to plan".  My solution for this is the ciphertext "617ed108bdc07e21d75e8f0c8a6f2c2e0cd2bb9592493f8c1b38323f752786e716fe5ba9e7d12e9a45b32ee1c49130c4". The explaination for this is included at the following path:
`./Problem 2 - AES ECB Flaws/Problem 2 AES ECB.txt`

## Problem 3
The objective for this problem was to create a function that encrypts input data under an unknown (randomly generated) key and, for CBC, IV. The function is to randomly decide whether to use ECB or CBC to encrypt the data. With this function, we are to design a program to determine whether the function used ECB or CBC. The program can be compiled using the provided Makefile and run like so: `./ecb_detection`. I will explain my implementation in two parts:

#### Encryption Function
I designed my encryption function to take in an input buffer and its size and a pointer to an output buffer and a reference to a variable to store its size in. In the function, I first create two temporary files - one for the input and one for the output. I then write the input to one of the files. and close it. Next, I prepare the encryption command (using rand() to decide whether to use ECB or CBC) and call the openssl command using system(). I then calculate the output length and allocation memory for the output string. I read the output file into the output buffer and close the files thereby letting them disappear (as they  are temporary). The calling function can then use the output buffer to get the encrypted data.

#### Main Program to Determine the Type of Encryption Used
Since ECB encrypts identical blocks of data into identical ciphers, I use a string that is two identical blocks as my input. If the first half of the ciphertext equals the second, the encryption function used ECB. Otherwise it used CBC. Since AES encryption schemes use 16 byte blocks, I made my input 32 bytes (each character is one byte). Both the first and second halves of the input are identical which should yeild the same for the output string. Next I call the encryption function and start looking at the data. Because AES adds one block of padding when encrypting plaintext that is an even number of blocks, the output ciphertext is actually 3 blocks long. The third block is the encrypted padding so I do not look at it. I focus on the first two blocks. If they are the same, then ECB was used. I iterate through the characters to determine this. When running my tests, the program got it right every time.

## Problem 4
The purpose of this problem was to look into SHA1 and dictionary attacks. The problem is split into two parts. The first is to use the dictionary given to crack an unsalted SHA1 hashed password. The second part requires adding the option of including salt when cracking the passwords. Each implementation and the outcomes are explained in more depth below. The final solution can be compiled using the included Makefile and run like the following:

Without Salt:
```
./sha1_password_crack 10kpwds.txt C604B40452110CA7B432EA2D51867F774EA4EB60
```

With Salt:
```
./sha1_password_crack 10kpwds.txt BD17A274120510B73CC32A41D1EDA0FC36ED458A V0aFg83KN01xCFRosTJ5
./sha1_password_crack 10kpwds.txt FA54A2C671B251D64060F2776072BF48590ABF2E NQe0P3ts18bSuNdAe13v
```

#### Part 1
My solution to the dictionary password cracking problem was to develop a program that takes in the dictionary file as a text file with one possible password per line and the hash with each of the bytes represented in two digit hex numbers. SHA1 always outputs a 20 byte hash and it is common to represent each of the 20 bytes in hex. In the program, I first open the dictionary file and then iterate through each line of it (thus each possible password). For each possible password, I first remove the newline and then hash it. I convert the output hash to hex and compare it against the passed in hex value. If they match, the password has been found and I say so. The hash given had the following password:

Hash: 0xC6 0x04 0xB4 0x04 0x52 0x11 0x0C 0xA7 0xB4 0x32 0xEA 0x2D 0x51 0x86 0x7F 0x77 0x4E 0xA4 0xEB 0x60
Password: goldeneye

#### Part 2
In part 2, the code from part 1 is modified to include salt. In the implementation, the salt is added to the front of the password before the password is hashed like so <salt><password>. For my code, this meant adding an optinal third argument for the salt. Then when preparing each potential password to be hashed, I first add the salt to the front of it. Then when displaying the output, I display the unsalted password. Everything else about the dictionary attack is the same. Though salting adds 2^n more potential hashes and is very affective at increasing the amount of time a brute force attack would take on a hash, it does not do much for a dictionary attack. Since the dictionary attack just hashes passwords, the only extra time added is the cost of hashing the salt as part of the password (assuming the salt is known). This does not add a significant amount of time to cracking the passwords. Using the hashes and salts provided, I got crack the following passwords:

Hash: 0xBD 0x17 0xA2 0x74 0x12 0x05 0x10 0xB7 0x3C 0xC3 0x2A 0x41 0xD1 0xED 0xA0 0xFC 0x36 0xED 0x45 0x8A
Salt: V0aFg83KN01xCFRosTJ5
Password: minemine

Hash: 0x73 0xB6 0x4B 0xE4 0xD4 0xF6 0xD8 0x38 0xDE 0x43 0x46 0x0C 0x60 0x78 0x05 0x14 0x18 0x75 0xFF 0x43
Salt: GhP49SwLN21VdeSsERt1
Password: minemine

Hash: 0xFA 0x54 0xA2 0xC6 0x71 0xB2 0x51 0xD6 0x40 0x60 0xF2 0x77 0x60 0x72 0xBF 0x48 0x59 0x0A 0xBF 0x2E
Salt: NQe0P3ts18bSuNdAe13v
Password: minemine


## Everything has been tested on Ubuntu and on Mac OS X with openssl installed. These must be installed to compile and run everything:

Mac:
```
brew install openssl
```

Ubuntu:
```
apt-get install openssl
apt-get install libssl-dev
```










