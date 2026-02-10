/* Program description and explanation*/
/*Simplified Steps*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define Max_File_Size 100

// Function Declaration
char* Read_File(const char *filename, int *length); 
int Write_File(const char *filename, const char *data);
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output);


int main(int argc, char* argv[]) {
    // Arguement check, terminate program if invalid arg count
    if(argc != 3){
        printf("Invalid number of arguments.\n");
        return 1;
    }

    /******************
        OFFLINE PHASE
    *******************/
    char* messageFileName = argv[1];
    char* indexArg = argv[2];

    // Read from message file
    int messageLength;
    unsigned char* messageWhole = Read_File(messageFileName, &messageLength);

    // Verify message length

    /* Create Merkle Hash Tree as array-based binary tree
    Index 0 = root
    Index 1-2 = level 1
    Index 3-4 = level 2
    Index 7-14 = leaves
    */
    // Program is designed for an 8-leaf MHT
    char* MHT[15] = {NULL};

    // Read each line of data, hash it, store in tree leaves
    char* token = strtok(messageWhole, "\n");
    char* hash = NULL;
    int i = 7;
    while(token != NULL){
        Compute_SHA256(token, sizeof(token), hash);
        // Copy hash to MHT[i]
        // Increment i
        // Get next token
    }

    /*Calculate root*/
    // Declare input string
    // for i from 6 to 0
        // Concatenate left, then right children of MHt[i] to input
        // Hash input and store into MHT[i]
        // Reset input string
    
    // Convert root to hex string
    // Write root hex string to file

    /******************
        ONLINE PHASE
    *******************/
    // Convert input argument index to MHT leaf index

    // [Still need to verify path format]
    // [Still need to plan out obtaining path]
    // ...
    // Free pointers
    return 0;
}

/* Helper Functions */

// Read File
char* Read_File(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }
    
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    
    // Remove trailing whitespace
    while (read_size > 0 && (buffer[read_size-1] == '\n' || 
                              buffer[read_size-1] == '\r' || 
                              buffer[read_size-1] == ' ')) {
        buffer[--read_size] = '\0';
    }
    
    *length = read_size;
    fclose(file);
    return buffer;
}

 // Write string to file
int Write_File(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}

// SHA256 hash
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return 0;
}