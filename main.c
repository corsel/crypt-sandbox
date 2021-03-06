#include <openssl/aes.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

unsigned char keyHash[SHA256_DIGEST_LENGTH];
unsigned char *inBuffer;
unsigned char *outBuffer;

FILE *inFile, *outFile;
long fileSize;

void clearBuffers()
{
	free(inBuffer);
	inBuffer = 0;
	free(outBuffer);
	outBuffer = 0;
}

int readFile(unsigned char *argFilename)
{
	clearBuffers();
	fileSize = -1;
	
	printf("debug - file name: %s\n", argFilename);
	inFile = fopen(argFilename, "r");
	if (!inFile)
	{
		printf("error - file not found: %s. skipping...\n", argFilename);
		return 1;
	}

	unsigned char outFilename[256];
	strcpy(outFilename, argFilename);
	strcat(outFilename, ".crp");
	outFile = fopen(outFilename, "w+");
	fseek(inFile, 0, SEEK_END);
	fileSize = ftell(inFile);
	printf("debug - readFile: file size is %li\n", fileSize);
	rewind(inFile);
	inBuffer = malloc(fileSize);
	outBuffer = malloc(fileSize + 256 - (fileSize % 256));
	
	fgets(inBuffer, fileSize + 1, inFile);
	
	return 0;
}

void encryptAes()
{
	AES_KEY aesKey;
	AES_set_encrypt_key(keyHash, 256, &aesKey);
	
	AES_encrypt(inBuffer, outBuffer, &aesKey);
	printf("debug - encrypted text: ");
	int i = 0;
	for (; i < 1024; i++)
	{
		if (outBuffer[i] == '\0')
			break;
		printf("%02x ", outBuffer[i]);
	};
	fputs(outBuffer, outFile);
	
	printf("\n");
}

void generateHash(unsigned char *argPassphrase)
{
	unsigned char key[SHA256_DIGEST_LENGTH];
	unsigned char *data;
	
	data = malloc(10 * sizeof(unsigned char));
	
	strcpy(key, argPassphrase);
	
	SHA256_CTX handle;
	SHA256_Init(&handle);
	SHA256_Update(&handle, key, strlen(key));
	SHA256_Final(keyHash, &handle);
	
	printf("debug - passphrase: %s\n\tsha256 hash: ", argPassphrase);
	int i = 0;
	for (; i < SHA256_DIGEST_LENGTH; i++)
	{
		printf("%02x", keyHash[i]);
	};
	printf("\n");
	
	free(data);
}

int main(int argc, char **argv)
{
	if (argc <= 1)
	{
		printf("error - needs at least 2 arguments.\n");
		return 1;
	}
	unsigned char keyBuffer[256];
	//TODO: check if entering 256+ chars is safe. 
	//TODO: masked input?
	printf("Please enter passphrase: ");
	scanf("%s", keyBuffer);
	generateHash(keyBuffer);
	int i = 1; 
	for (; i < argc; i++)
	{
		if (!readFile(argv[i]))
		{
			
			encryptAes();
			fclose(inFile);
			fclose(outFile);
		}
	}
	clearBuffers();
	return 0;
}
