// Alice reads the message from the ”Message.txt” file and the he shared seed from the ”SharedSeed.txt” file. 
// Then the secret key is generated from the shared seed based on utilizing the ChaCha20 PRNG function from OpenSSL. The key size must match the message length.
// Then the Hex format of the key is written in a file named “Key.txt”.
// XOR the message with the secret key to obtain the ciphertext: (Ciphertext = Message XOR Key).
// Write the Hex format of the ciphertext in a file named “Ciphertext.txt”.
// Once Bob has processed the message, Alice reads Bob’s computed hash from ”Hash.txt”.
// If the comparison is successful, Alice can be confident that Bob has received the accurate message. She then writes ”Acknowledgment Successful” in a 
    // file called ”Acknowledgment.txt.” Conversely, if the comparison fails, she records ”Acknowledgment Failed.”

// Simplified steps
//  - Read message and seed from files
//  - Generate key 
//  - Write key to file
//  - Encrypt message using XOR with key
//  - Write ciphertext to file
//  - Read hash from file and compare

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#define Max_File_Name_Size 100

// global variable declarations
int messageSize;
int seedSize;
char messageFileName[Max_File_Name_Size]; 
char seedFileName[Max_File_Name_Size];
char *filePointer = messageFileName;

// Function declarations
// unsigned char *readFile(FILE *file, size_t *length);
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);

int main(int argc, char *argv[]) {

    char *userMessageFileArg = argv[1];
    char *userSeedFileArg = argv[2];

    // If the user enters the wrong number of arguments, the program will not run
    if(argc == 3)
    {
        // Initialize pointers to argv arguments
        char *userMessageFileArg = argv[1];
        userSeedFileArg = argv[2];
        
        // The user's input is copied to the messageFileName and seedFileName arrays, 
        // both loops use the same pointer named "filePointer" to copy the strings
        for( ; *userMessageFileArg != '\0'; userMessageFileArg++)
        {
            *filePointer = *userMessageFileArg;
            filePointer++;
            // printf("%s", messageFileName);
            // printf("\n");
        }
        *filePointer = '\0';
        for(filePointer = seedFileName; *userSeedFileArg != '\0'; userSeedFileArg++)
        {
            *filePointer = *userSeedFileArg;
            filePointer++;
        }
        *filePointer = '\0';
    }

    unsigned char *message = Read_File(messageFileName, &messageSize);
    unsigned char *seed = Read_File(seedFileName, &seedSize);

    // Edge case checks
        // Message must be greater than or equal to 32 bytes
        if (messageSize < 32){
            printf("Message must be at least 32 bytes.");
            return 0;
        }
        
        // Seed must be exactly 32 bytes
        if (seedSize != 32){
            printf("Seed must be exactly 32 bytes, not %d bytes.", seedSize);
            return 0;
        }

    // allocate memory for key
    unsigned char *key = malloc(messageSize);
    if (!key) {
        printf("Memory allocation for key failed.");
        return 0;
    }
    char *convertedKey = malloc(messageSize); 
    if (!convertedKey) {
        printf("Memory allocation for converted key failed.");
        return 0;
    }
    char *convertedCiphertext = malloc(messageSize); 
    if (!convertedCiphertext) {
        printf("Memory allocation for converted ciphertext failed.");
        return 0;
    }
    
    // Initial attempt to use openssl evp
    // // Initialize OpenSSL EVP for ChaCha20 to generate key
    // EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, NULL);

    // // Convert message length to int and generate key, passing the key buffer, 
    // // seed, message size, and cipher context structure
    // int outLength = (int)messageSize;
    // EVP_EncryptUpdate(ctx, key, &outLength, seed, messageSize);
    // EVP_CIPHER_CTX_free(ctx);

    // Use PRNG function to generate key
    key = PRNG(seed, seedSize, messageSize);

    // Write key to "Key.txt" in hexadecimal format, every byte becomes two hex characters
    Convert_to_Hex(convertedKey, key, messageSize);
    Write_File("Key.txt", convertedKey, messageSize);

    // XOR message with key to create ciphertext
    unsigned char *ciphertext = malloc(messageSize);
    if(!ciphertext) {
        printf("Memory allocation for ciphertext failed.");
        return 0;
    }
    for (int i = 0; i < messageSize; i++) {
        ciphertext[i] = message[i] ^ key[i];
    }

    // Write ciphertext to "Ciphertext.txt" in hexadecimal format
    Write_File("Ciphertext.txt", convertedCiphertext, messageSize);

    sleep(1);

    // Read Bob's computed hash from "Hash.txt"






// print section for debugging
    // SEED
    // printf("Seed: %s\n", seed);

    // SEED SIZE
    // printf("Seed size: %d bytes\n", seedSize);

    // MESSAGE
    printf("Message: %s\n", message);

    // MESSAGE SIZE
    // printf("Message size: %d bytes\n", messageSize);

    // CIPHERTEXT
    // printf("Ciphertext: %s\n", ciphertext);

    // CIPHERTEXT SIZE
    // printf("Ciphertext size: %d bytes\n", messageSize);

    // KEY
    printf("Key: ");
    for (int i = 0; i < messageSize; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");


    // free allocated memory
    free(message);
    free(seed);
    free(key);
    

    return 0;
}

// Helper functions

// unsigned char *readFile(FILE *file, size_t *length) {
//     // Move the file pointer to the end of the file
//     fseek(file, 0, SEEK_END);
//     // Get the current position of the file pointer (which is the size of the file)
//     messageSize = ftell(file);
//     *length = messageSize;
//     // Move the file pointer back to the beginning of the file
//     rewind(file);
//     if (messageSize <= 0){
//         printf("file is empty.");
//         return NULL;
//     }

//     // Allocate memory to hold the file contents, return NULL if malloc fails
//     unsigned char *buffer = malloc(messageSize);
//     if (!buffer) return NULL;

//     // Easy library function to read file contents into buffer
//     fread(buffer, 1, messageSize, file);

//     return buffer;
// }

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
    // printf("Hex format: %s\n", output);  //remove later
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
