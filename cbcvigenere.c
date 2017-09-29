#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

//------------------------------------------------------------------+
// University of Central Florida									|
// CIS3360 - Fall 2016												|
// Program Author: Thomas Angelo									|
//------------------------------------------------------------------+

// ascii value ranges for english chars
#define MAX_CHAR 122
#define MIN_CHAR 97
#define MAX_CAP 91
#define MIN_CAP 64

// creates and prints encrypted characters
char *generateCText (FILE *fp, char *ctext, char *pw, char *iv, int blockSize, int *plainCount, int *padCount) {
	char c, d, *cbuff = NULL;

	int i = 0, pwLen, lineBreak = 0, blockCount = 0, k = 0;
	pwLen = strlen(pw);

	ctext = malloc(sizeof(char) * 5000);
	if(ctext == NULL) {
		return NULL;
	}
	cbuff = malloc(sizeof(char) * (pwLen + 1));
	if(!cbuff) {
		return NULL;
	}

	printf("Clean Plaintext:\n\n");
	while(1) { 

		c = fgetc(fp);
		if ((int)c <= MAX_CHAR && (int)c >= MIN_CHAR) { // strips non-alphabet chars
			printf("%c", c);
			c = c % MIN_CHAR; //0-25 charset
			lineBreak++;
			if (i < pwLen) {
				d = (c + (iv[i] % MIN_CHAR)); // gives iv shifted char
				ctext[i] = ((d + (pw[i % pwLen] % MIN_CHAR)) % 26) + MIN_CHAR; // shifts back to ascii
			}
			else {
				d = (c + (ctext[i - pwLen] % MIN_CHAR));
				ctext[i] = ((d + (pw[i % pwLen] % MIN_CHAR)) % 26) + MIN_CHAR; //97-122 max ascii vals
			}
			i++;
			(*plainCount)++;
		}
		else if((int)c < MAX_CAP && (int)c > MIN_CAP){ // checks for capital ascii val
			c = tolower(c);
			printf("%c", c);
			c = c % MIN_CHAR; //0-25 charset
			lineBreak++;
			if (i < pwLen) {
				d = (c + (iv[i] % MIN_CHAR)); // gives iv shifted char **
				ctext[i] = ((d + (pw[i % pwLen] % MIN_CHAR)) % 26) + MIN_CHAR; // shifts by keyword
			}
			else {
				d = (c + (ctext[i - pwLen] % MIN_CHAR));
				ctext[i] = ((d + (pw[i % pwLen] % MIN_CHAR)) % 26) + MIN_CHAR; //97-122 max ascii vals
			}
			i++;
			(*plainCount)++;
		}
		else if (feof(fp)) {
			// leftover text to be padded with x's and encrypt
			k = i;
			while((k % pwLen) != 0) {
				c = 'x' % MIN_CHAR;
				d = (c + (ctext[k - pwLen] % MIN_CHAR));
				ctext[k] = ((d + (pw[k % pwLen] % MIN_CHAR)) % 26) + MIN_CHAR; //97-122 max ascii vals
				k++;
				(*padCount)++;
			}
			ctext[k] = '\0';
			break;
		}
		if (lineBreak == 80) {
			printf("\n");
			lineBreak = 0;
		}
	}
	if (lineBreak < 80)
		printf("\n");
	printf("\n");

	return ctext;

} 

int main(int argc, char **argv) { 

	char *ctext = NULL;
	// 4 total args, <exe> <filename> <password> <vector>
	if (argc < 4) { 
		printf("Too few arguments given, format is: ./<exe> <filename> <password> <vector>\n");
		return 1;
	}

	int c1, c2, blockSize;  
	c1 = blockSize = strlen(argv[2]);
	c2 = strlen(argv[3]);

	// checks vector and passkey length
	if (c1 != c2) {
		fprintf(stderr, "error, password and vector are not the same length\n");
		return 1;
	}
	//intro text
	printf("\nCBC Vigenere by Thomas Angelo\n");
	printf("Plaintext file name: %s\n", argv[1]);
	printf("Vigenere keyword: %s\n", argv[2]);
	printf("Initialization vector: %s\n\n", argv[3]);

	int fcheck = 0;
	FILE *fp = NULL;
	fcheck = strlen(argv[1]);

	//checks command line for file extension
	if (argv[1][fcheck - 4] != '.') {
		char *newFname = NULL;
		newFname = malloc(sizeof(char) * (fcheck + 5));
		//appends ".txt" to file argument if not already there
		strcpy(newFname, argv[1]);
		newFname[fcheck] = '.';
		newFname[fcheck + 1] = 't';
		newFname[fcheck + 2] = 'x';
		newFname[fcheck + 3] = 't';
		newFname[fcheck + 4] = '\0';
		//printf("new fname %s\n", newFname);
		fp = fopen(newFname, "r");
	}
	else {
		fp = fopen(argv[1], "r");	
	}
	
	if(fp == NULL){
		printf("error reading file\n");
		return 1;
	}

	int *plainCount = NULL;
	plainCount = malloc(sizeof(int));
	int *padCount = NULL;
	padCount = malloc(sizeof(int));

	ctext = generateCText(fp, ctext, argv[2], argv[3], blockSize, plainCount, padCount);
	if(ctext == NULL){
		printf("error reading file\n");
		return 1;
	}

	// prints ciphertext line breaks
	int ctSize = 0;
	ctSize = strlen(ctext);
	int j = 0;
	printf("Ciphertext:\n\n");
	while(j < ctSize) {
		printf("%c", ctext[j]);
		j++;
		if (j % 80 == 0 && j > 0)
			printf("\n");
	}

	printf("\n\nNumber of characters in clean plaintext file: %d\n", *plainCount);
	printf("block size = %d\n", blockSize);
	printf("Number of pad characters added: %d\n", *padCount);

	// cleanup memory
	free(ctext);
	free(plainCount);
	free(padCount);
	ctext = NULL;
	fclose(fp);

	return 0;
}