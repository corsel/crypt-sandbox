#include <openssl/aes.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

unsigned char keyHash[SHA256_DIGEST_LENGTH];

void generateHash(unsigned char *argPass)
{
	unsigned char key[SHA256_DIGEST_LENGTH];
	unsigned char *data;
	
	data = malloc(10 * sizeof(unsigned char));
	
	strcpy(key, argPass);
	printf("debug - check: %s\n", key);
	
	SHA256_CTX handle;
	SHA256_Init(&handle);
	SHA256_Update(&handle, key, strlen(key));
	SHA256_Final(keyHash, &handle);
	
	printf("debug - sha256 hash: ");
	int i = 0;
	for (; i < SHA256_DIGEST_LENGTH; i++)
	{
		printf("%02x", keyHash[i]);
	};
	printf("\n");
	
	free(data);
}

void loadFile(char *argFileName)
{
	FILE *handle;
	handle = fopen(argFileName, "r");
	fclose(handle);
}

int main(int argc, char **argv)
{
	if (argc == 1)
	{
		printf("error - no arguments passed. terminating.\n");
		return 1;
	}
	generateHash(argv[1]);	
	return 0;
}
