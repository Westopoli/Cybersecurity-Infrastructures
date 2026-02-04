// Puzzle Generation Program
//      note: this is the first of 3 programs working together to implement a client-server puzzle for DDoS prevention.

// Server program reads the challenge data from Challenge$i.txt which contains the timestamp || server_nonce
// Then it reads the difficulty from Difficulty$i.txt
// It writes the challenge to puzzle_challenge.txt as a hex string and the difficulty to puzzle_k.txt as ASCII integer

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

char* Read_File(const char *filename, int *length);
void Write_File(char fileName[], char input[], int input_length);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash);
int Read_Int_From_File(const char *filename);
// changed to void from int to accomodate new Write_File function
void Write_Int_To_File(const char *filename, int value);

int main(int argc, char *argv[]) {

    char *userChallengeFileArg = argv[1];
    char *userDifficultyFileArg = argv[2];
    
    // Read challenge data
    int challenge_len;
    int difficulty;
    char *challenge = Read_File(userChallengeFileArg, &challenge_len);
    // printf("read challenge\n");

    // Read the difficulty
    difficulty = Read_Int_From_File(userDifficultyFileArg);
    // printf("read difficulty\n");

    // Write the challenge to puzzle_challenge.txt as a hex string
    // printf("convert bytes to hex\n");
    Write_File("puzzle_challenge.txt", (char *)challenge, challenge_len);
    printf("write to puzzle_challenge.txt\n");

    // Write the difficulty to puzzle_k.txt
    Write_Int_To_File("puzzle_k.txt", difficulty);
    printf("write to puzzle_k.txt\n");
    

    return 0;
}  


/*
    File I/O Functions
*/

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

// This function produced a segmentation fault
//  // Write string to file
// int Write_File(const char *filename, const char *data) {
//     FILE *file = fopen(filename, "w");
//     if (!file) {
//         fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
//         return -1;
//     }
    
//     fprintf(file, "%s", data);
//     fclose(file);
//     return 0;
// }

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

/*
    Hex Conversion Functions
*/

 // Convert hex string to byte array
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len) {
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: Hex string length must be even\n");
        return -1;
    }
    
    int byte_len = hex_len / 2;
    for (int i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            fprintf(stderr, "Error: Invalid hex character at position %d\n", i * 2);
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }
    
    return byte_len;
}

 // Convert byte array to hex string
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}

/*
    Cryptographic Functions
*/

// SHA256 hash
int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return 0;
}

/*
    Utility Functions
*/

int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}

void Write_Int_To_File(const char *filename, int value) {
    char buffer[32];
    sprintf(buffer, "%d", value);
    Write_File((char *)filename, buffer, sizeof(buffer));
}

void Print_Hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
