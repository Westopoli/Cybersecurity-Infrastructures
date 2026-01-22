// Alice reads the message from the ”Message.txt” file and the he shared seed from the ”SharedSeed.txt” file. 
// Then the secret key is generated from the shared seed based on utilizing the ChaCha20 PRNG function from OpenSSL. The key size must match the message length.
// Then the Hex format of the key is written in a file named “Key.txt”.
// XOR the message with the secret key to obtain the ciphertext: (Ciphertext = Message XOR Key).
// Write the Hex format of the ciphertext in a file named “Ciphertext.txt”.
// Once Bob has processed the message, Alice reads Bob’s computed hash from ”Hash.txt”.
// If the comparison is successful, Alice can be confident that Bob has received the accurate message. She then writes ”Acknowledgment Successful” in a 
    // file called ”Acknowledgment.txt.” Conversely, if the comparison fails, she records ”Acknowledgment Failed.”

#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#define Max_File_Name_Size 100

// global variable declarations
size_t messageSize;
size_t seedSize;
char messageFileName[Max_File_Name_Size]; 
char seedFileName[Max_File_Name_Size];
char *filePointer = messageFileName;

// Function forward declaration
unsigned char *readFile(FILE *messageFile, size_t *length);

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
    // printf("Message File: %s\n", messageFileName);
    // printf("Seed File: %s\n", seedFileName);

    FILE *messageFile = fopen(messageFileName, "r");
    if(messageFile == NULL){
        printf("unable to open message file.");
        return 0;
    }
    FILE *seedFile = fopen(seedFileName, "r");
    if(seedFile == NULL){
        printf("unable to open seed file.");
        return 0;
    }

    unsigned char *message = readFile(messageFile, &messageSize);
    unsigned char *seed = readFile(seedFile, &seedSize);

    // print message and seed for debugging
    printf("Message: %s\n", message);
    printf("Seed: %s\n", seed);

    // TODO: Implement key generation, encryption, and acknowledgment logic here
    // Edge case checks
        // Message must be greater than or equal to 32 bytes
        if (messageSize < 32){
            printf("Message must be at least 32 bytes.");
            return 0;
        }
        
        // Seed must be exactly 32 bytes
        if (seedSize != 32){
            printf("Seed must be exactly 32 bytes, not %zu bytes.", seedSize);
            return 0;
        }

    // allocate memory for key
    unsigned char *key = malloc(messageSize);
    if (!key) {
        printf("Memory allocation for key failed.");
        return 0;
    }
    
    // Initialize OpenSSL EVP for ChaCha20 to generate key
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, NULL);

    // Convert message length to int and generate key, passing the key buffer, 
    // seed, message size, and cipher context structure
    int outLength = (int)messageSize;
    EVP_EncryptUpdate(ctx, key, &outLength, seed, messageSize);
    EVP_CIPHER_CTX_free(ctx);

    // // prints the key in hexadecimal (readable)
    // for (int i = 0; i < messageSize; i++) {
    //     printf("%02x", key[i]);
    // }

    // Write key to "Key.txt" in hexadecimal format
    // FILE *keyFile = fopen("Key.txt", "w");



    // close files after reading
    fclose(messageFile);
    fclose(seedFile);

    // free allocated memory
    free(message);
    free(seed);
    free(key);
    

    return 0;
}

// Helper functions

unsigned char *readFile(FILE *file, size_t *length) {
    // Move the file pointer to the end of the file
    fseek(file, 0, SEEK_END);
    // Get the current position of the file pointer (which is the size of the file)
    messageSize = ftell(file);
    *length = messageSize;
    // Move the file pointer back to the beginning of the file
    rewind(file);
    if (messageSize <= 0){
        printf("file is empty.");
        return NULL;
    }

    // Allocate memory to hold the file contents, return NULL if malloc fails
    unsigned char *buffer = malloc(messageSize);
    if (!buffer) return NULL;

    // Easy library function to read file contents into buffer
    fread(buffer, 1, messageSize, file);

    return buffer;
}