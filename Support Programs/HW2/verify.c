// Puzzle Generation Program
// This program acts as the server's verification of the client's proof of computation for DoS 
// prevention. It reads the challenge (similar to the client) and computes the hash
// with the client's nonce and checks that it has the correct number of leading 0 bits.

// Pseudocode
// Input: Challenge, difficulty k, solution nonce
// Output: Accept or Reject
// 1) Read challenge from puzzle challenge.txt
// 2) Read difficulty k from puzzle k.txt
// 3) Read nonce from solution nonce.txt
// 4) Construct data = challenge || nonce
// 5) Compute hash = SHA256(data)
// 6) Check if hash has k leading zero bits
// 7) If yes: Write ”ACCEPT”, exit 0
// 8) If no: Write ”REJECT”, exit 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <math.h>

char* Read_File(const char *filename, int *length);
void Write_File(char fileName[], char input[], int input_length);
int Hex_To_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Bytes_To_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash);
int Read_Int_From_File(const char *filename);
// changed to void from int to accomodate new Write_File function
void Write_Int_To_File(const char *filename, int value);
void Int_To_Binary(int n, char *binary);
void Count_Leading_Zeros(unsigned char *hash, int *zeros);
void Print_Byte_Binary(unsigned char byte);
void Print_Hex(const char *label, const unsigned char *data, int len);

int main(int argc, char *argv[]) {
    
    char *userChallengeFileArg = argv[1];
    char *userDifficultyFileArg = argv[2];
    char *userNonceFileArg = argv[3];

    // Read challenge as char 
    int challenge_hex_len;
    int difficulty;
    char *challenge_in_hex = Read_File(userChallengeFileArg, &challenge_hex_len);

    char *challenge_in_bytes = (char *)malloc(challenge_hex_len / 2);
    int challenge_len = Hex_To_Bytes(challenge_in_hex, (unsigned char *)challenge_in_bytes, challenge_hex_len);

    // Read difficulty as integer
    difficulty = Read_Int_From_File(userDifficultyFileArg);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    int nonce_hex_len;
    char *nonce_hex = Read_File(userNonceFileArg, &nonce_hex_len);

    // // Debugging different nonce values between programs
    // const char *label = "Hex";
    // Print_Hex(label, (const unsigned char*)nonce_hex, nonce_hex_len);

    // Hex to Bytes 
    unsigned char nonce_bytes[nonce_hex_len / 2];
    unsigned int nonce_len = Hex_To_Bytes(nonce_hex, nonce_bytes, nonce_hex_len);

    // printf("Difficulty: %d\n", difficulty);
    // printf("Nonce: ");
    // for(int i = 0; i < nonce_len; i++) {
    //     Print_Byte_Binary(nonce_bytes[i]);
    // }
    // printf("\n");

    // print challenge_len and nonce_len for debugging
    // printf("Challenge Len: %d\n", challenge_len);
    // printf("Nonce Len (%%u): %u\n", nonce_len);

    // // print challenge_in_bytes for debugging
    // printf("Challenge Bytes: ");
    // for(int i = 0; i < challenge_len; i++) {
    //         Print_Byte_Binary(challenge_in_bytes[i]);
    // }
    // printf("\n");

    // construct data = challenge || nonce
    unsigned char data[challenge_len + nonce_len];
    memcpy(data, challenge_in_bytes, challenge_len);
    memcpy(data + challenge_len, nonce_bytes, nonce_len);

    // printf("Data: ");
    // for(int i = 0; i < sizeof(data); i++) {
    //     Print_Byte_Binary(data[i]);
    // }
    // printf("\n");

    Compute_SHA256(data, challenge_len + nonce_len, hash);

    printf("Hash: ");
    for(int i = 0; i < sizeof(hash); i++) {
        Print_Byte_Binary(hash[i]);
    }
    printf("\n");

    int zeros = 0;
    Count_Leading_Zeros(hash, &zeros);

    printf("Leading Zeros: %d\n", zeros);
    printf("Difficulty: %d\n", difficulty);

    char accept[6] = "ACCEPT";
    char reject[6] = "REJECT";

    if(zeros >= difficulty) {
        Write_File("verification_result.txt", accept, strlen(accept));
        printf("ACCEPT\n");
        free(challenge_in_hex);
        free(challenge_in_bytes);
        free(nonce_hex);
        exit(0);
    }
    else {
        Write_File("verification_result.txt", reject, strlen(reject));
        printf("REJECT\n");
        free(challenge_in_hex);
        free(challenge_in_bytes);
        free(nonce_hex);
        exit(1);
    }

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

    // printf("Iteration\n");
    // for(int i = 0; i < *length; i++) {
    //     Print_Byte_Binary(buffer[i]);
    // } 
    // printf("\n");
    return buffer;
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

/*
    Hex Conversion Functions
*/

 // Convert hex string to byte array
int Hex_To_Bytes(const char *hex, unsigned char *bytes, int hex_len) {
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
int Bytes_To_Hex(const unsigned char *bytes, int byte_len, char *hex) {
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

void Int_To_Binary(int n, char *binary)
{
    int binaryReversed[256];
    int iterator = 255;
    while (n > 0) {
        binaryReversed[iterator] = n % 2;
        n = n / 2;
        iterator--;
    }
    int start_pos = iterator + 1;  // First position we wrote to
    int length = 256 - start_pos;
    
    for(int i = 0; i < length; i++) {
        binary[i] = binaryReversed[start_pos + i] + '0';
    }
    binary[length] = '\0';
}

void Count_Leading_Zeros(unsigned char *hash, int *zeros) {
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        // if entire byte is 0, we don't have to do partial bits
        if(hash[i] == 0) {
            *zeros += 8;  
        } 
        else {
            // count leading zeros in this byte
            unsigned char byte = hash[i];
            for(int bit = 7; bit >= 0; bit--) {
                // and the byte with another byte that only contains a 1 in the bit position 
                // (starts left, moves right with each iteration)
                // As soon as the result is non-zero we break
                if(byte & (1 << bit)) 
                    break;  
                
                (*zeros)++;
            }
            break;  
        }
    }
}

void Print_Byte_Binary(unsigned char byte) {
    for(int bit = 7; bit >= 0; bit--) {
        printf("%d", (byte >> bit) & 1);
    }
}