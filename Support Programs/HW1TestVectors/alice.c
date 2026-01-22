// Alice reads the message from the ”Message.txt” file and the he shared seed from the ”SharedSeed.txt” file. 
// Then the secret key is generated from the shared seed based on utilizing the PRNG function from OpenSSL. The key size must match the message length.
// Then the Hex format of the key is written in a file named “Key.txt”.
// XOR the message with the secret key to obtain the ciphertext: (Ciphertext = Message XOR Key).
// Write the Hex format of the ciphertext in a file named “Ciphertext.txt”.
// Once Bob has processed the message, Alice reads Bob’s computed hash from ”Hash.txt”.
// If the comparison is successful, Alice can be confident that Bob has received the accurate message. She then writes ”Acknowledgment Successful” in a 
    // file called ”Acknowledgment.txt.” Conversely, if the comparison fails, she records ”Acknowledgment Failed.”

#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>

#define Max_File_Name_Size 100

// global variable declarations
size_t size;
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

    unsigned char *message = readFile(messageFile, &size);
    unsigned char *seed = readFile(seedFile, &size);

    // print message and seed for debugging
    printf("Message: %s\n", message);
    printf("Seed: %s\n", seed);

    // TODO: Implement key generation, encryption, and acknowledgment logic here

    // close files after reading
    fclose(messageFile);
    fclose(seedFile);

    return 0;
}

// Helper functions

unsigned char *readFile(FILE *messageFile, size_t *length) {
    // Move the file pointer to the end of the file
    fseek(messageFile, 0, SEEK_END);
    // Get the current position of the file pointer (which is the size of the file)
    size = ftell(messageFile);
    // Move the file pointer back to the beginning of the file
    rewind(messageFile);
    if (size <= 0){
        printf("file is empty.");
        return NULL;
    }

    // Allocate memory to hold the file contents, return NULL if malloc fails
    unsigned char *buffer = malloc(size);
    if (!buffer) return NULL;

    // Easy library function to read file contents into buffer
    fread(buffer, 1, size, messageFile);

    return buffer;
}