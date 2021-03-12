CS427-Project1
Benjamin Eavenson
benjamin.eavenson@wsu.edu

This is an implementation of wsu-crypt, a block encryption algorithm that takes a 64-bit key and 64-bit blocks.

Files included in this archive:

README.md  - Thats this file.
Makefile   - Makefile for the program. Contains make instructions for compiling and removing the executable program.
wsucrypt.c - Source code file for wsu-crypt. This contains all of the code for the project.

To compile, run make.

To encrypt a file with this program, run wsu-crypt with the -e flag.
To decrypt a file with this program, run wsu-crypt with the -d flag.
Use the -k <keyfile> flag to denote which file contains the hex representation of the key.
Use the -in <infile> flag to denote which file you want to encrypt/decrypt.
Use the -out <outfile> flag to denote which file you want the program to send output to.

Examples:

./wsu-crypt -e -k key.txt -in plain.txt -out cipher.txt
./wsu-crypt -d -k key.txt -in cipher.txt -out decoded.txt


While writing this, I experienced some troubles with the I/O functions writing bytes in the wrong order. I figured that this was
due to some inconsistency with endian-ness, and so I implemented a -disable-fix flag that stops the program from swapping the bytes
back around when writing after a decrypt, in the case that this is just a problem on my machine.

If when running this you find that after decryption the characters are correct but ordered incorrectly, I recommend decrypting using
this -disable-fix flag:

./wsu-crypt -d -k key.txt -in cipher.txt -out decoded.txt -disable-fix

