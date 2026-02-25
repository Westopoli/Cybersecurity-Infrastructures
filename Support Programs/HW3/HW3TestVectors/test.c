#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash);
int Encrypt_AES(const unsigned char* plaintext, int plaintextlen, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext);
int Decrypt_AES(const unsigned char* ciphertext, int ciphertextlen, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
void Print_Byte_Binary(unsigned char byte);
char* Read_File(const char *filename, int *length);
int Compute_HMAC(const unsigned char* data, const int datalen, const unsigned char* key, const int keylen, unsigned char* HMAC, const int HMAC_size);



int main(){
    // int cipher_size;
    // int key_size;
    // unsigned char* ciphertext = Read_File("CorrectCiphertexts1.txt", &cipher_size);
    // unsigned char* key = Read_File("CorrectKeys1.txt", &key_size);
    // printf("%s\n%s\n", ciphertext, key);

    /*Tried hex ct hex key, hex ct byte key, byte ct byte key*/
    unsigned char* ciphertext = "4e3e39ce7e8e67113a3835f4d004249319659fb5ae505355052844108f4613d7b643a3eb82fb74bd24aae7128a9087b5860cf071611d1b79e20aeb2e714e84352ed13f7ec0396b32e69b43a2607e4559a9af61e18b53cc711a8e7341666741a2d0683efba32c00129d19f578fc26cba487f85d1a93d4def0f7b3fabc3be6136a607e3535506160e4473a73537311766186e325af95ef4f5a9b4b6651e9b149175cb4a5b1571c2d6adbdad6d5360cf9633d498c6b75f2bef6baf3d8eedc2e137e241a8419de555f726308f9df9ad2cc4fcd1e301e865106ebca81b424e943330f149ba6bd5bddcbc950a941ffdf4e380269c07c3232d0c6a74c069dd21fd6384986b9817fe5e0de73cc852ac4f4fb9c1eb2a3112eccef0f45133b49becf1a50c9c6b1745e3d94cf4a871ff507b39cec855d39b4d93554aa01978680e317db801eb7a585e36580a3028e22e1db7345aba661ee95c8116fb88275f6ea95ed1560522c61caffc008f9343d94b04d9b8410f63ead827b2352205891092c2a6d76b854ff145c9e5f55ac2168aa6f324c23beb40d93d7db01a1f20ec50e4de456fbc646845a4c4973534ce8bcd419f5f109f0e0953bc976e118d5991e9b4756d6258cb20c8325e4eea4da2a28d731f5586ff35c25529097571ca951ca7cdba35048af555c13310835f3e4f9242a608c13a4a8df2efc3341672c76ac7ce1f53437ac9351502327a81163bf6eb835abf729de09b4f6edde47a96221aa2bdd3b98d515cefdf4e5ccf87b91586490f7fa5017062e5d4b8658cc3a41732aedaf5788937bab4c8ed786a00363ea4567be4a0fc650dd6a3078b0f98e80b44defc2e8118e2a9263570fa2b22a471b92d54f295be579e95b57293a5cfd62214fe9554d796d9de9f33706b85045526b1e4e7958ae3799f6fff5a44468928c01e1aa3f54f055e401a0071b88c5842711df135c77a67ab80024c76d44262b6d3e3c1163489b69fac9026cb6538d6d8a8c72c69857c9806714516467d2a0b9e9febe7ded8d99cbcd635a41ef9c293591b847bc70a2ece71595546fef9fb0da22406e5326703cfd80861a74ce2455f111161970e110ce94b57aa5a963e06ea21fe55fef4e66ec55e5fb2b85542e75fce610cfb8e82d3c8053b681dce5b276b96374fb0b80f7d9d0c74c50f0a751bba7b814becb0ce6670f63648bbb820be2a3b7d882217978b5154fe57299f8c36b2ecba121b01e83bd789c8ddce55c3c0d29ea0ace40cb8df7ff752adcb68c7b6036ee1bd3ec092b0a8c2175d2bb523b7318c389026fe6e9072e1c17700271aeadbf0da5e776a85495e227cec898b09095671df3d33ea7a7da0e6f5f1650d73b198abea2c9d35147b403f127adc5c8db361b542f40994e54b3daa7d82171789c24322d7bd8b92b1f91c7aa95cd975e9f96bc6f1b4ce3efc6db7c105265";
    unsigned char* key = "59f2fe9f93c2233bddcaedf724c1a3cfa217b0d6e5c7df4f67019861df48980c";
    unsigned char key_bytes[32]; 
    unsigned char ciphertext_bytes[512];
    Hex_to_Bytes(ciphertext, ciphertext_bytes, 1024);
    Hex_to_Bytes(key, key_bytes, 64);
    // printf("%s\n%s\n", ciphertext, key);
    unsigned char HMAC[256] = {""};
    Compute_HMAC(ciphertext_bytes, 1024, key_bytes, 32, HMAC, 64);
    printf("%s\n", HMAC);
    unsigned char hex[32] = {""};
    Bytes_to_Hex(HMAC, 32, hex);
    printf("%s\n", hex);


    return 0;
}

int Compute_HMAC(const unsigned char* data, const int datalen, const unsigned char* key, const int keylen, unsigned char* HMAC, const int HMAC_size){
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);    
    EVP_MAC_init(ctx, key, keylen, params);
    EVP_MAC_update(ctx, data, datalen);
    size_t HMAC_len;
    EVP_MAC_final(ctx, HMAC, &HMAC_len, HMAC_size);

    EVP_MAC_free(mac);
    EVP_MAC_CTX_free(ctx);

    return 0;
}

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

