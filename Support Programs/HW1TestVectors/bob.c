// Bob reads the ciphertext from the ”Ciphertext.txt” file.
// Read the shared seed from the ”SharedSeed.txt” file. 
// Generate the secret key from the shared seed based on utilizing the PRNG function from OpenSSL. The key size must match the message length.
// XOR the received ciphertext with the secret key to obtain the plaintext: (plaintext = ciphertext XOR key).
// Write the decrypted plaintext in a file named “Plaintext.txt”.
// Hash the plaintext via SHA256 and writes the Hex format of the hash in a file named ”Hash.txt” for Alice to verify

// Simplified steps:
//  - Read ciphertext and seed from files
//  - Generate key
//  - Decrypt ciphertext using XOR with key
//  - Write plaintext to file
//  - Hash plaintext and write hash to file

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#define Max_File_Name_Size 100

// global variable declarations
int seedSize;
int ciphertextSize;
char seedFileName[Max_File_Name_Size];
char *filePointer = seedFileName;

// Function declarations
// unsigned char *readFile(FILE *file, size_t *length);
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Convert_to_Binary(unsigned char output[], char input[], int inputlength);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);

int main(int argc, char *argv[]) {

    // If the user enters the wrong number of arguments, the program will not run
    if(argc == 2)
    {
        // Initialize pointers to argv arguments
        char *userSeedFileArg = argv[1];
        
        // The user's input is copied to the messageFileName and seedFileName arrays, 
        // both loops use the same pointer named "filePointer" to copy the strings
        for( ; *userSeedFileArg != '\0'; userSeedFileArg++)
        {
            *filePointer = *userSeedFileArg;
            filePointer++;
            // printf("%s", messageFileName);
            // printf("\n");
        }
        *filePointer = '\0';
    }
    
    // Read seed from file
    unsigned char *seed = Read_File(seedFileName, &seedSize);

    // Seed must be exactly 32 bytes
    if (seedSize != 32){
        printf("Seed must be exactly 32 bytes, not %d bytes.", seedSize);
        return 0;
    }

    // Read ciphertext from "Ciphertext.txt"
    unsigned char *ciphertext = Read_File("Ciphertext.txt", &ciphertextSize);

    Convert_to_Binary(ciphertext, (char *)ciphertext, ciphertextSize);

    ciphertextSize = ciphertextSize / 2; // Adjust size after converting from hex to binary
    
    // Generate key using PRNG
    unsigned char *key = malloc(ciphertextSize);
    if (!key) {
        printf("Memory allocation for key failed.");
        return 0;
    }

    key = PRNG(seed, seedSize, ciphertextSize);

    // Decrypt ciphertext using XOR with key
    unsigned char *plaintext = malloc(ciphertextSize);
    if (!plaintext) {
        printf("Memory allocation for plaintext failed.");
        return 0;
    }
    for(int i = 0; i < ciphertextSize; i++) {
        plaintext[i] = ciphertext[i] ^ key[i];
    }

    


// print section for debugging
    // SEED
    printf("Seed: %s\n", seed);

    // SEED SIZE
    // printf("Seed size: %d bytes\n", seedSize);

    // CIPHERTEXT
    // printf("Ciphertext: %s\n", ciphertext);

    // CIPHERTEXT SIZE
    printf("Ciphertext size: %d bytes\n", ciphertextSize);

    // KEY
    printf("Key: ");
    for (int i = 0; i < ciphertextSize; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
        
    // PLAINTEXT
    printf("Plaintext: %s\n", plaintext);

    // Write plaintext to "Plaintext.txt"
    Write_File("Plaintext.txt", (char *)plaintext, ciphertextSize);
  
    free(seed);
    return 0;
}

// Helper functions

unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

void Write_File(char fileName[], char input[], int input_length){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  //fputs(input, pFile);
  fwrite(input, 1, input_length, pFile);
  fclose(pFile);
}

void Show_in_Hex (char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    printf("Hex format: %s\n", output);  //remove later
}

void Convert_to_Binary(unsigned char output[], char input[], int inputlength)
{
    for (int i=0; i<inputlength/2; i++){
        sscanf(&input[2*i], "%2hhx", &output[i]);
    }
    // printf("Binary format: ");  //remove later
    // for (int i = 0; i < inputlength/2; i++) {
    //     printf("%02x", output[i]);
    // }
    // printf("\n");
}

unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    // allocate cipher context and output buffer
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *pseudoRandomNumber = malloc(prnglen);

    // initialize ChaCha20 with the seed and a zero nonce
    unsigned char nonce[16] = {0};
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce);

    // filling zero buffer with zeros
    unsigned char zeros[prnglen];
    memset(zeros, 0, prnglen);

    int outlen;
    // generate pseudo-random bytes 
    EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    // finalize encryption
    EVP_EncryptFinal(ctx, pseudoRandomNumber, &outlen);

    // free cipher context
    EVP_CIPHER_CTX_free(ctx);
    return pseudoRandomNumber;
}

unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return hash;
}
