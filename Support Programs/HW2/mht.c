/* Program description and explanation*/
/*Simplified Steps*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MESSAGE_BYTE_SIZE 32

// Function Declaration
char* Read_File(const char *filename, int *length); 
int Write_File(const char *filename, const char *data);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);


int main(int argc, char* argv[]) {
    // Arguement check, terminate program if invalid arg count
    if(argc != 3){
        printf("Invalid number of arguments.\n");
        return 1;
    }

    /******************
        OFFLINE PHASE
    *******************/
    char* message_filename = argv[1];
    char* index_arg = argv[2];

    // Verify index argument format

    // Read from message file
    int message_length;
    unsigned char* message_whole = Read_File(message_filename, &message_length);

    // Verify message length

    /* Initial attempt to build MHT and calc leaf hashes
    char* MHT[15] = {NULL};
    char* token = strtok(messageWhole, "\n");
    char* hash = NULL;
    int i = 7;
    while(token != NULL){
        hash = Hash_SHA256(token, strlen(token) + 1);
        MHT[i] = malloc(Message_Byte_Size);
        if(!MHT[i]){
            printf("Memory allocation for MHT node failed.");
            return 0;
        }
        memcpy(MHT[i++], hash, Message_Byte_Size);
        free(hash);
        printf("%s[String End]\n", MHT[i-1]); 
        token = strtok(NULL, "\n"); 
    }*/
     
    /* Merkle Hash Tree using array-based binary tree 
    Rows 7-14 = leaves, data indices 1-8
    Rows 3-6 = level 2
    Rows 1-2 = level 1
    Row 0 = root
    */
    /*Using a 2D array this time instead of 1D array of pointers since all elements 
    will contain same length hashes. Avoids memory allocation and increases simplicity.*/
    unsigned char MHT[15][MESSAGE_BYTE_SIZE];

    // Parse whole message into 32 byte messages
    unsigned char* token = strtok(message_whole, "\n");
    unsigned char* hash;
    
    // MHT Rows 7-14 align with data indices 1-8
    int i = 7;
    while(token != NULL){
        hash = Hash_SHA256(token, MESSAGE_BYTE_SIZE);
        memcpy(MHT[i++], hash, MESSAGE_BYTE_SIZE);
        free(hash);
        token = strtok(NULL, "\n");
    }
    
    // Holds concatenated children input for hash
    unsigned char input[2 * MESSAGE_BYTE_SIZE];

    // Calculate hashes for rest of tree
    for(i = 6; i >= 0; i--){
        // Concatenate left and right child of MHT[i] into input
        memcpy(input, MHT[2 * i + 1], MESSAGE_BYTE_SIZE);  // Left child
        memcpy(input + MESSAGE_BYTE_SIZE, MHT[2 * i + 2], MESSAGE_BYTE_SIZE);  // Right child
        
        // Hash children and store in MHT
        hash = Hash_SHA256(input, 2 * MESSAGE_BYTE_SIZE);
        memcpy(MHT[i], hash, MESSAGE_BYTE_SIZE);
        free(hash);
    }

    // Convert root to hex string
    unsigned char hex[MESSAGE_BYTE_SIZE]; 
    Bytes_to_Hex(MHT[0], MESSAGE_BYTE_SIZE, hex);

    // Write root hex string to file
    Write_File("TheRoot.txt", hex);

    /******************
        ONLINE PHASE
    *******************/
    // Convert input argument index to MHT leaf index
    i = atoi(&index_arg[1]);
    i += 6;

    // Calculate path
    unsigned char path[6 * MESSAGE_BYTE_SIZE + 3];
    while(i != 0){
        if(i % 2 == 1)  // i odd --> left child
            hash = MHT[i + 1];
        else            // i even --> right child
            hash = MHT[i - 1];
        printf("Current i = %d\n", i);
        Bytes_to_Hex(hash, MESSAGE_BYTE_SIZE, hex);
        strcat(path, hex);
        strcat(path, "\n");
        
        i = (i - 1) / 2;    // Parent
    }
    
    // Write path hex string to file
    Write_File("ThePath.txt", path);

    // Free pointers
    free(message_whole);
    
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

int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}