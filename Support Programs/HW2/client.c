// Puzzle Solving Program - Client Side

// Client program reads the challenge and difficulty, computes the puzzle solution by finding the right 
// nonce (k leading bits are 0), and write solution to repsective files.

// Psuedocode: 
//  1. Read challenge from puzzle_challenge.txt as a char (hex string) and convert to byte array
//  2. Read difficulty from puzzle_k.txt as an integer
//  3. Starting from 0, increment values 
    //  a. Construct data = challenge || nonce
    //  b. Compute SHA256(data)
    //  c. Check if hash has k leading zero bits
// 4. To check: 
    // Full 0 bytes k/8
    // Partial bits k%8
    // Use bit masking for partial byte check
// 5. Write nonce to solution_nonce.txt as Hex string 
// 6. Write iteration count to solution_iterations.txt as ASCII integer 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

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

int main(int argc, char *argv[]) {

    char *userChallengeFileArg = argv[1];
    char *userDifficultyFileArg = argv[2];

    // Read challenge as char 
    int challenge_hex_len;
    int difficulty;
    char *challenge_in_hex = Read_File(userChallengeFileArg, &challenge_hex_len);
    // for(int i = 0; i < sizeof(challenge_in_hex); i++){
    //     printf("%d", challenge_in_hex[i]);
    // }
    // printf("\n");
    char *challenge_in_bytes = (char *)malloc(challenge_hex_len / 2);
    int challenge_len = Hex_To_Bytes(challenge_in_hex, (unsigned char *)challenge_in_bytes, challenge_hex_len);
    // for(int i = 0; i < sizeof(challenge_in_bytes); i++){
    //     printf("%d", challenge_in_bytes[i]);
    // }
    // printf("\n");

    // Read difficulty as integer
    difficulty = Read_Int_From_File(userDifficultyFileArg);
    // printf("Difficulty Int: %d\n", difficulty);

    // Starting from nonce = 0, increment and check for solution
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int nonce = 0;
    unsigned long long iterations = 0;
    int found = 1;
    int zeros = 0;
    
    while (found) {
        // construct hash input = challenge || nonce
        for( ; iterations < 1ULL << (difficulty - 1); iterations++) {
            printf("Iteration: %llu\n", iterations);
            unsigned char data[challenge_len + sizeof(nonce)];
            memcpy(data, challenge_in_bytes, challenge_len);
            memcpy(data + challenge_len, &nonce, sizeof(nonce));
            // int bits_we_care_about = difficulty % 8;

            // compute SHA256 hash
            Compute_SHA256(data, sizeof(data), hash);
            nonce++;

            Count_Leading_Zeros(hash, &zeros);

            if(zeros > difficulty) {
                found = 0;
                break;
            }

            // for(int i = 0; i < challenge_len; i++) {
            //     // before iterating through this hash, check if we've already found enough zero bits
            //     // if(zero_counter >= difficulty) {
            //     //     found = 0;
            //     //     break;
            //     // }

            //     // // Full byte level check
            //     // if (hash[i] == 0) {
            //     //     zero_counter += 8;
            //     //     printf("\nFRONT IS 0\n");
            //     //     printf("%d\n", hash[i]);
            //     //     break;
            //     // }

            //     // // Get the relevant bits from the current byte
            //     // unsigned char *temp_byte_digits = malloc(sizeof(char) * 8);
                
            //     // // unnecessary conversion
            //     // // Hex_To_Bytes((char *)hash, temp_byte_digits, 2);
            //     // // for(int i = 0; i < 8; i++){
            //     // //     printf("%c", temp_byte_digits[i]);
            //     // // }
            //     // // printf("\n");

            //     // // Partial bit level check
            //     // if (partial_zero_counter < bits_we_care_about) {
            //     //     for(int i = 0; i < bits_we_care_about; i++) {
            //     //         if (temp_byte_digits[i] == 0)
            //     //             partial_zero_counter++;
            //     //     }
            //     // }
            //     // // found can be set to one because if we get to this point, all full bytes before it are zero
            //     // if (partial_zero_counter == bits_we_care_about) {
            //     //     zero_counter += bits_we_care_about;
            //     //     found = 0;
            //     //     break;
            //     // }

                
            // }   
        }
        // if(iterations == 2047 && found == 0)
        //     break;
    }

    // Write nonce to solution_nonce.txt as hex string
    char nonce_as_bytes[sizeof(nonce) * 2 + 1];
    Int_To_Binary(nonce, nonce_as_bytes);
    Bytes_To_Hex((unsigned char *)&nonce, sizeof(nonce), nonce_as_bytes);
    Write_File("solution_nonce.txt", nonce_as_bytes, sizeof(nonce_as_bytes));

    // int testing = 127;
    // char *binary = (char *)malloc(257);
    // Int_To_Binary(testing, binary);
    // for(int i = 0; i < 256; i++) {
    //     printf("%c", binary[i]);
    // }
    // printf("\n");

    // Write iteration count to solution_iterations.txt as ASCII integer
    Write_Int_To_File("solution_iterations.txt", iterations);

    free(challenge_in_bytes);
    // free(binary);

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
        if(hash[i] == 0) {
            *zeros += 8;  // entire byte is zero
        } else {
            // count leading zeros in this byte
            unsigned char byte = hash[i];
            for(int bit = 7; bit >= 0; bit--) {
                if(byte & (1 << bit)) break;  // found a 1 bit
                *zeros++;
            }
            break;  // stop after first non-zero byte
        }
    }
}
