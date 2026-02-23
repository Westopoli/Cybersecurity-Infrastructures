/* This program implements an 8-leaf Merkle Hash Tree (MHT) using an array-based binary tree. 
The program has an online and offline phase. In the online phase it reads 8 newline-separated 
256-bit lines of random data from the message text file and accepts a message index. 
Then hashes each message using SHA256 to create the leaves of the tree. The upper node 
layers and root are calculated by concatenating its children (left-to-right) and hashing the result. 
The root is converted into a hex string and written to the "TheRoot.txt" file.

In the offline phase, the program computes a verification path based on the message index input
argument. Starting at the respective message index leaf and ending at the root, the program obtains
the hash value of the node's sibling, converts it to a hex string, adds it to the path, then considers
its parent. Each node of the path is written to the "ThePath.txt" file, where each node of the path is
separated by a newline character.*/

/*Simplified Steps
Offline Phase
- Reads messages and index from files
- Calculates MHT 
- Convert MHT root to hex and write to file

Online Phase
- Builds verification path based on index
- Converts path to hex and write to file
*/

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

    // Verify index argument format (First char M, second char 1-8)
    if(index_arg[0] != 'M' || (index_arg[1] < '1' || index_arg[1] > '8') || strlen(index_arg) != 2){
        printf("Invalid message index format.\n");
        return 1;
    }

    // Read from message file
    int message_whole_length;
    unsigned char* message_whole = Read_File(message_filename, &message_whole_length);

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

    // For each message, hash and store in leaf
    while(token != NULL){
        hash = Hash_SHA256(token, MESSAGE_BYTE_SIZE);
        memcpy(MHT[i++], hash, MESSAGE_BYTE_SIZE);
        free(hash);
        token = strtok(NULL, "\n");     // Get next message
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
    unsigned char hex[2 * MESSAGE_BYTE_SIZE + 1];   // 64 Hex char + \0
    Bytes_to_Hex(MHT[0], MESSAGE_BYTE_SIZE, hex);

    // Write root hex string to file
    Write_File("TheRoot.txt", hex);

    /******************
        ONLINE PHASE
    *******************/
    // Convert input argument index to MHT leaf index
    // ie. M1 --> MHT index 7
    i = atoi(&index_arg[1]);
    i += 6;

    // Calculate path, convert to hex
    // Path (3 concatenated hash pairs, 3 \n, 1 \0)
    unsigned char path[6 * MESSAGE_BYTE_SIZE + 4] = {'\0'};
    while(i != 0){
        // Add hash of node's sibling to path
        if(i % 2 == 1)  // i odd --> left child
            hash = MHT[i + 1];  // Use right sibling hash
        else            // i even --> right child
            hash = MHT[i - 1];  // Use left sibling hash
        Bytes_to_Hex(hash, MESSAGE_BYTE_SIZE, hex); 
        strcat(path, hex);
        strcat(path, "\n");
        
        // Move up a level
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

 // Convert byte array to hex string
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}