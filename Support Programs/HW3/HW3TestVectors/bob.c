#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_MESSAGES 100
#define MAX_MESSAGE_LENGTH 2049
#define KEY_LENGTH 32
#define HMAC_LENGTH 32

void Write_File(char fileName[], char input[], int input_length);
int Compute_HMAC(const unsigned char* data, const int datalen, const unsigned char* key, const int keylen, unsigned char* HMAC, const int HMAC_size);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Read_File (char fileName[], int *fileLen);
int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash);
int Encrypt_AES(const unsigned char* plaintext, int plaintextlen, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext);
int Decrypt_AES(const unsigned char* ciphertext, int ciphertextlen, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
void Print_Byte_Binary(unsigned char byte);

struct MessageInfo {
    unsigned char plainText[MAX_MESSAGE_LENGTH];
    int plainTextLen;
    unsigned char cipherText[MAX_MESSAGE_LENGTH];
    int cipherTextLen;
    unsigned char key[KEY_LENGTH];
    int keyLen;
    unsigned char hmac[KEY_LENGTH];
    int hmacLen;
    unsigned char aggregateHmac[KEY_LENGTH];
    int aggregateHmacLen;
};

// Steps
/*  Reads shared seed
    Read each ciphertext
    Read aggregated HMAC
    For each ciphertext
        Compute HMAC with key and ciphertext
        Aggregate HMAC
        Update key
    Compare aggregated HMACs
        If not equal leave program
        If equal begin decryption
    Decrypt each ciphertext
    Write each plaintext to file
*/

int main(int argc, char *argv[]) {

    // argc check
    if(argc != 4){
        printf("Invalid number of arguments.\n");
        return 1;
    }

    unsigned char buffer[MAX_MESSAGE_LENGTH * MAX_MESSAGES];
    strcspn(buffer, "\n");

    struct MessageInfo messages[MAX_MESSAGES];

    // Given IV for AES encrypt/decrypt
    unsigned char IV[16] = "abcdefghijklmnop";

    int i = 0;
    int message_len = 0;
    FILE *fp = fopen(argv[2], "r");
    while(fgets(buffer, MAX_MESSAGE_LENGTH, fp) != NULL){
        // Copies message into buffer w/o newline, gets message len
        message_len = strcspn(buffer, "\n");
        buffer[message_len] = '\0';
        // printf("Buffer: %s\nMessage_Len: %d\n", buffer, message_len);
        Hex_to_Bytes(buffer, messages[i].cipherText, message_len);
        messages[i++].cipherTextLen = message_len / 2;
        // memcpy(messages[i++].cipherText, buffer, message_len);
        // printf("Struct cipher len: %d\n", messages[i].cipherTextLen);
        // printf("Struct cipher: %s\n", messages[i].cipherText);
        
        // Skip empty buffer
        fgets(buffer, MAX_MESSAGE_LENGTH, fp);

    }

    int message_amount = i;

    // printf("%d\n", i);
    // for(i = 0; i < 10; i++){
    //     printf("%s\n", messages[i].cipherText);
    // }

    // Initial attempt at reading ciphertexts into messages structs
    // unsigned char* ciphertext_all = malloc(MAX_MESSAGE_LENGTH * MAX_MESSAGES);
    // int len;
    // ciphertext_all = Read_File(argv[2], &len);

    // printf("Len:%d\nCiphertext:%s\n", len, ciphertext_all);
    
    // Read shared seed
    unsigned char *userSeedFileArg = argv[1];
    int seed_len;
    unsigned char* seed = Read_File(userSeedFileArg, &seed_len);
    // printf("%s\n", seed);

    // Calculate first key
    memcpy(messages[0].key, PRNG(seed, seed_len, KEY_LENGTH), KEY_LENGTH);

    buffer[0] = '\0';

    for(i = 0; i < message_amount; i++){
        messages[i].keyLen = KEY_LENGTH;
        messages[i].hmacLen = HMAC_LENGTH;

        // HMAC
        Compute_HMAC(messages[i].cipherText, messages[i].cipherTextLen, messages[i].key, messages[i].keyLen, messages[i].hmac, messages[i].hmacLen);

        if(i == 0)
            Compute_SHA256(messages[i].hmac, messages[i].hmacLen, messages[i].aggregateHmac);
        else{
            unsigned char hash_input[HMAC_LENGTH * 2];

            // concat last hmac and current hmac
            memcpy(hash_input, messages[i-1].aggregateHmac, HMAC_LENGTH);
            memcpy(hash_input + HMAC_LENGTH, messages[i].hmac, HMAC_LENGTH);
            Compute_SHA256(hash_input, 2 * messages[i].hmacLen, messages[i].aggregateHmac);
        }
        messages[i].aggregateHmacLen = HMAC_LENGTH;

        // Hash key -> next key
        Compute_SHA256(messages[i].key, KEY_LENGTH, messages[i + 1].key);
    }
    
    // Get correct aggregated HMAC
    int file_len;
    unsigned char correct_aggregated_HMAC[HMAC_LENGTH];
    memcpy(buffer, Read_File(argv[3], &file_len), 2 * HMAC_LENGTH);
    Hex_to_Bytes(buffer, correct_aggregated_HMAC, 2 * HMAC_LENGTH);

    unsigned char hex[MAX_MESSAGE_LENGTH];
    // Confirm if calculated aggregate HMAC is valid
    if((memcmp(correct_aggregated_HMAC, messages[message_amount - 1].aggregateHmac, HMAC_LENGTH) == 0)){
        for(i = 0; i < message_amount; i++){
            messages[i].plainTextLen = Decrypt_AES(messages[i].cipherText, messages[i].cipherTextLen, messages[i].key, IV, messages[i].plainText);
            memcpy(buffer + i * (messages[i].plainTextLen + 1), messages[i].plainText, messages[i].plainTextLen);
            if(i < message_amount - 1)
                buffer[i * (messages[i].plainTextLen + 1) + messages[i].plainTextLen] = '\n';
        }
        Write_File("Plaintexts.txt", buffer, i * (messages[i - 1].plainTextLen + 1) - 1);
    }
    else{
        printf("Incorrect aggregated HMAC. Verficiation failed.\n");
    }

    fclose(fp);
    return 0;
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

int Compute_HMAC(const unsigned char* data, const int datalen, const unsigned char* key, const int keylen, unsigned char* HMAC, const int HMAC_size){
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if(!mac){
        printf("mac failed.\n");
        return 1;
    }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if(!ctx){    
        printf("ctx failed.\n");
        return 1;    
    }
    EVP_MAC_init(ctx, key, keylen, params);
    EVP_MAC_update(ctx, data, datalen);
    size_t HMAC_len = 0;
    EVP_MAC_final(ctx, HMAC, &HMAC_len, HMAC_size);
    
    EVP_MAC_free(mac);
    EVP_MAC_CTX_free(ctx);

    return 0;
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
	// fgets(output, temp_size, pFile); // only read first message
    fread(output, 1, temp_size-1, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

int Encrypt_AES(const unsigned char* plaintext, int plaintextlen, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext){
    // Allocate memory for cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Initialize context to perform AES encryption in CTR mode
    EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv, 1);    // Encrypt = 1

    int offsetPointer = 0;
    int ciphertextlen = 0;
    // Pass output(ciphertext) and input(plaintext), perform encryption
    EVP_CipherUpdate(ctx, ciphertext, &offsetPointer, plaintext, plaintextlen);

    // Finalize operation
    EVP_CipherFinal_ex(ctx, ciphertext + offsetPointer, &ciphertextlen);

    // printf("ENCRYPTION:\n");
    // printf("Ciphertext length: %d\n", offsetPointer + ciphertextlen);
    
    // Free context
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int Decrypt_AES(const unsigned char* ciphertext, int ciphertextlen, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext){
    // Allocate memory for cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){    
        printf("ctx failed.\n");
        return 1;    
    }
    int len = 0, total_len = 0;
    // Initialize context to perform AES decryption in CTR mode
    EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv, 0);    // Encrypt = 0

    int offsetPointer = 0;
    int plaintextlen = 0;
    // Pass output(plaintext) and input(ciphertext), perform decryption
    EVP_CipherUpdate(ctx, plaintext, &offsetPointer, ciphertext, ciphertextlen);
    
    // Finalize operation
    EVP_CipherFinal_ex(ctx, plaintext + offsetPointer, &plaintextlen);

    // printf("DECRYPTION:\n");
    // printf("Plaintext length: %d\n", offsetPointer + plaintextlen);
    // unsigned char hex[MAX_MESSAGE_LENGTH];

    // Bytes_to_Hex(plaintext, ciphertextlen, hex);
    // printf("Plaintext: %s\n", hex);
    // Free context
    EVP_CIPHER_CTX_free(ctx);
    return offsetPointer;
}

int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return 0;
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

int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}

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

void Print_Byte_Binary(unsigned char byte) {
    for(int bit = 7; bit >= 0; bit--) {
        printf("%d", (byte >> bit) & 1);
    }
}

