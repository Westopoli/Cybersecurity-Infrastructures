#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash);
int Encrypt_AES(const unsigned char* plaintext, int plaintextlen, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext);
int Decrypt_AES(const unsigned char* ciphertext, int ciphertextlen, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
void Print_Byte_Binary(unsigned char byte);

int main(int argc, char *argv[]) {

    int plainlen = 1025;
    unsigned char plaintext[1025] = "JACjFRIbgPWvL7wtskCioNfUySuvmJS0225B4LyK6FMNySTLRpLFa8JKaoEftPCDR5T2A2ZKMp0GwcPBSlH4ZRDEntkFEbW5r6DVP5Ol8mfo6fv5a8iXOWIxoNdEFBMVXAv7NxIHIhKITIxGwLGQUcPieU1RAxyV5g6otI3rlIQApE9qLkJ3SpnesaRhrNC4YKxtQh3XHScrYWZ7iF2l4SKGXhLrh5mcULk1j7C6i66OnZzAmKFmU1zmv28QSUIdTJmeAtxm21F2sJZCfdtMQA5eIHttXKYR16tHy5kfjjCSNscs8CXJcm56U6Imad3s6y7Gc5cuSHmtmq0xG3ON9xpc9fXUhkZKLl0AILbtK0EBbOrQ66vddLoxcPus4hC10dXBZaWjzOORvrDhVNQqT00mpGC7EwcgeDrnJaVhhH85dfp8y7mmuQdlVhA452mKKaNOGKtGE5w9s6qv5FEnS9nmmVYHnDF7pgyr8SX5HE4qi8GptxyCe2tVX8GUcF7Lynu8CaqpuFIz5XYBTfbX6LkBLZHiFWooblQAhRnjt6YMZVksMAnm0nYEpjAn3Kiu72AM5hHhbGHp38jTBlDiU05wU6F2HUipfnDrMatxcrFNX3Hb01q8AJJitXBpUsMfeY3urMEZJuvbahHgEFH5Vn2TF6jTwVcT2kl2rMGX1VJdXEN9LOYjB3WLnN1gzVBqky3MmvwlDago431SHOTR42SyLZ2vTLEO9rKivDbuxxNOb5jmvmvDSfOlPdPrtGpIxkEhyE86Rs35oTB17W82z0nQWwr7GMLhRFEMGIVnOjV88gNiKnkdYARizYAUW0Vcpri0NVBakF1Zac019TMESeqx2nTUJUWHES7X7nn3iSaLlnQOl9aHLZwWRbz9pYhfdxXjOGsPmwrpIRpaLHZdhZqNmYxYRnUVWJml9EEvkAayq9CPrd7TgIjyDcPf23yWppyVTcr7NnOJjKvTFjhwPggsOQ406Lr3wVrUL0PAcSaMmjsMoNkWxLuIVTiTPaj1";

    unsigned char IV[16] = "abcdefghijklmnop";

    const char keyHexText[65] = "59f2fe9f93c2233bddcaedf724c1a3cfa217b0d6e5c7df4f67019861df48980c";

    unsigned char keyBuffer[32];       
    unsigned char cipherBuffer[plainlen];
    unsigned char decryptedBuffer[plainlen];

    // Hex to bytes on key
    Hex_to_Bytes(keyHexText, keyBuffer, 64);

    // Encrypt
    Encrypt_AES(plaintext, plainlen, keyBuffer, IV, cipherBuffer);

    // Convert ciphertext to hex
    char hex[4096] = {0};
    Bytes_to_Hex(cipherBuffer, plainlen, hex);
    // printf("Ciphertext (hex): %s\n", hex);
    // printf("\n\n");

    // Decrypt
    Decrypt_AES(cipherBuffer, plainlen, keyBuffer, IV, decryptedBuffer);

    // Print decrypted text
    // printf("Decrypted: %s\n", decryptedBuffer);

    // compare two buffers, if they are the same, print success message, otherwise print failure message
    if (memcmp(decryptedBuffer, plaintext, plainlen) == 0) {
        printf("Decryption successful, plaintext matches decrypted text.\n");
    }
    else {
        printf("Decryption failed, plaintext does not match decrypted text.\n");
    }

    return 0;
}

// Still needs implementation
// int HMAC(){
//     EVP_MAC_CTX *ctx = EVP_MAC_CTX_new();
//     EVP_MAC_init();
//     EVP_MAC_Update();
//     EVP_MAC_Final();
//     EVP_MD_MAC_free(ctx);

//     return 0;
// }

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
    int len = 0, total_len = 0;
    // Initialize context to perform AES decryption in CTR mode
    EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv, 0);    // Encrypt = 0

    int offsetPointer = 0;
    int plaintextlen = 0;
    // Pass output(plaintext) and input(ciphertext), perform decryption
    EVP_CipherUpdate(ctx, plaintext, &offsetPointer, ciphertext, ciphertextlen);
    
    // Finalize operation
    EVP_CipherFinal_ex(ctx, plaintext + offsetPointer, &plaintextlen);

    // add null character at the end of decrypted plaintext
    plaintext[offsetPointer + plaintextlen] = '\0';

    // printf("DECRYPTION:\n");
    // printf("Plaintext length: %d\n", offsetPointer + plaintextlen);
    
    // Free context
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return 0;
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

