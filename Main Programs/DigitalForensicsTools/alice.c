/*
Forward-Secure and Aggregate Digital Forensics Tools
Alice (Logging Machine) Program Description

In addition to forward-secure and aggregate MACs, we also introduce a forward-secure symmetric encryp-
tion. In this way, this tool will offer compromise-resilient encryption, integrity and authentication with compactness
(i.e., O(1) cryptographic tag size) in the symmetric cryptography setting.

It puts in action AES, SHA256, HMAC, hash-chains and hash functions in an integrated
manner. A secure and professional (e.g., side-channel resistant and optimization) implementation of the below al-
gorithm can offer a very high-security for real-life applications. The potential applications include but not limited
to secure voting, electronic banking system or other critical use-cases, wherein digital forensic investigations must
be conducted after the interface of active adversaries.

Technical Details: PRNG using Chacha20, SHA256, HMAC-SHA256, and AES-CTR in OpenSSL. The program is run as two separate 
executables - ”Alice” (Logging machine) and ”Bob” (Auditor) that communicate through text files. 

Pseudocode
    Reads shared seed/messages from file 
    Uses PRNG to create initial symmetric key
    For every message M
        Compute ciphertext C(i) = Encrypt(key(i), M(i))
        Individual HMAC: S(i) = HMAC(key(i), M(i))
        Aggregate HMAC: S(i) = Hash(S(1, i-1) || S(i))
            For case S(1, 1), the input will be just S(1)
            S(1, 2) = Hash(S(1, 1) || S(2))
            S(1, 3) = Hash(S(1, 2) || S(3))
            ...
        Update key for every message: key(i+1) = Hash(key(i))
    Alice Writes in Hex
        Keys in Keys.txt (multiple lines)
        Ciphertexts in Ciphertexts.txt (multiple lines)
        Individual HMACs in IndividualHMACs.txt (multiple lines)
        Aggregated HMACs in AggregateHMAC.txt

Apologies in advance for the mixing of camel case and snake case lol
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_MESSAGES 100
#define MAX_MESSAGE_LENGTH 1024
#define KEY_LENGTH 32
#define HEX_LENGTH (KEY_LENGTH * 2)

/* Function declarations*/
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
int Encrypt_AES(const unsigned char* plaintext, int plaintextlen, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Compute_HMAC(const unsigned char* data, const int datalen, const unsigned char* key, const int keylen, unsigned char* HMAC, const int HMAC_size);

// Struct to encapsulate message data
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

int main(int argc, char *argv[]) {
    
    unsigned char IV[16] = "abcdefghijklmnop";

    if(argc != 3) {
        printf("Incorrect number of arguments.\n");
        return 1;
    }

    // Reads shared seed/messages from file
    unsigned char* messagesAll = malloc(MAX_MESSAGES * MAX_MESSAGE_LENGTH);
    int len;
    messagesAll = Read_File(argv[1], &len);
    int numMessages = len / MAX_MESSAGE_LENGTH;

    char *userSeedFileArg = argv[2];
    int seedSize;

    unsigned char* seed = Read_File(userSeedFileArg, &seedSize);

    struct MessageInfo messages[MAX_MESSAGES];
    int currentPos = 0;
    int i = 0;
    int currentMessage = 0;

    // Loop through each individual message till newline character reached, store information about location, copy message to struct, increment
    // This could be a function, but for our purposes we only do this once, so it's fine to have it in main
    while (i < len && currentMessage < MAX_MESSAGES) {
        // Find the next newline
        int messageLen = 0;
        while (messagesAll[i] != '\n') {
            messageLen++;
            i++;
            // If end of file, break
            if (i >= len) {
                break; 
            }
        }
        
        // Copy the message by calculating the offset from start
        // currentPos is the start of the message, i is the end
        currentPos = i - messageLen;
        memcpy(messages[currentMessage].plainText, messagesAll + currentPos, messageLen);
        messages[currentMessage].plainTextLen = messageLen;
        messages[currentMessage].cipherTextLen = messageLen;

        // Remove trailing delimiter byte if it exists (0x01 in this case)
        while (messages[currentMessage].plainTextLen > 0 && 
        messages[currentMessage].plainText[messages[currentMessage].plainTextLen - 1] == 0x01) {
            messages[currentMessage].plainTextLen--;
        }
       
        // Message has been copied, i moves past newline, currentMessage increments
        i++; 
        currentMessage++;
    }

    // allocate memory for key
    unsigned char *key = malloc(MAX_MESSAGE_LENGTH);
    if (!key) {
        printf("Memory allocation for key failed.");
        return 0;
    }
    
    // generate key using PRNG with seed
    key = PRNG(seed, seedSize, KEY_LENGTH);
    messages[0].keyLen = KEY_LENGTH;
    memcpy(messages[0].key, key, KEY_LENGTH);
    
    for (int i = 0; i < currentMessage; i++) {
        messages[i].cipherTextLen = messages[i].plainTextLen;
        Encrypt_AES(messages[i].plainText, messages[i].plainTextLen, key, IV, messages[i].cipherText);

        // Individual HMAC: S(i) = HMAC(key(i), E(i))
        Compute_HMAC(messages[i].cipherText, messages[i].cipherTextLen, key, KEY_LENGTH, messages[i].hmac, KEY_LENGTH);
        messages[i].hmacLen = KEY_LENGTH;
        // Aggregate HMAC: S(i) = Hash(S(1, i-1) || S(i))
        if (i == 0) {
            // first hmac is just a hash of the first message's hmac
            unsigned char *hashOutput = Hash_SHA256(messages[i].hmac, KEY_LENGTH);
            memcpy(messages[i].aggregateHmac, hashOutput, KEY_LENGTH);
            messages[i].aggregateHmacLen = KEY_LENGTH;
            free(hashOutput);
        }
        else {
            unsigned char *hashInput = malloc(HEX_LENGTH);

            // concat last hmac with current hmac
            memcpy(hashInput, messages[i-1].aggregateHmac, KEY_LENGTH);
            memcpy(hashInput + KEY_LENGTH, messages[i].hmac, KEY_LENGTH);

            // hash it and store it in aggregateHmac
            unsigned char *hashOutput = Hash_SHA256(hashInput, HEX_LENGTH);
            memcpy(messages[i].aggregateHmac, hashOutput, KEY_LENGTH);
            messages[i].aggregateHmacLen = KEY_LENGTH;
            free(hashInput);
            free(hashOutput);
        }
        // Update key for every message: key(i+1) = Hash(key(i))
        unsigned char *newKey = malloc(KEY_LENGTH);
        newKey = Hash_SHA256(key, KEY_LENGTH);
        memcpy(key, newKey, KEY_LENGTH);
        memcpy(messages[i+1].key, key, KEY_LENGTH);
        messages[i+1].keyLen = KEY_LENGTH;
        free(newKey);
    }

// Alice Writes in Hex
    // Keys in Keys.txt (multiple lines)
    char keysHex[currentMessage * (HEX_LENGTH + 1)];
    int keysLocation = 0;
    for(int i = 0; i < currentMessage; i++) {
        char temp[HEX_LENGTH + 1];
        Bytes_to_Hex(messages[i].key, KEY_LENGTH, temp);
        memcpy(&keysHex[keysLocation], temp, HEX_LENGTH);
        keysLocation += HEX_LENGTH;
        if(i < currentMessage - 1) 
            keysHex[keysLocation++] = '\n';
    }
    
    Write_File("Keys.txt", keysHex, keysLocation);
    
    // Ciphertexts in Ciphertexts.txt (multiple lines)
    FILE *pFile = fopen("Ciphertexts.txt", "w");
    for(int i = 0; i < currentMessage; i++) {
        char temp[MAX_MESSAGE_LENGTH * 2 + 1];
        Bytes_to_Hex(messages[i].cipherText, messages[i].plainTextLen, temp);
        int hexLen = messages[i].plainTextLen * 2;
        
        fwrite(temp, 1, hexLen, pFile);
        if(i < currentMessage - 1) {
            fwrite("\n", 1, 1, pFile);
        }
    }
    fclose(pFile);

    // Individual HMACs in IndividualHMACs.txt (multiple lines)
    char individualHMACsHex[currentMessage * (HEX_LENGTH + 1)];
    int location = 0;
    for(int i = 0; i < currentMessage; i++) {
        char temp[HEX_LENGTH + 1];
        Bytes_to_Hex(messages[i].hmac, KEY_LENGTH, temp);
        memcpy(individualHMACsHex + (i * (HEX_LENGTH + 1)), temp, HEX_LENGTH);
        location += HEX_LENGTH;
        if(i < currentMessage - 1) {
            individualHMACsHex[location++] = '\n';
        }
    }
    
    Write_File("IndividualHMACs.txt", individualHMACsHex, location);
    // Aggregated HMAC in AggregateHMAC.txt
    char aggregateHex[HEX_LENGTH + 1];
    Bytes_to_Hex(messages[currentMessage-1].aggregateHmac, KEY_LENGTH, aggregateHex);
    Write_File("AggregatedHMAC.txt", aggregateHex, HEX_LENGTH);

    free(key);
    free(messagesAll);
    
    return 0;
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

int Encrypt_AES(const unsigned char* plaintext, int plaintextlen, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext){
    // Allocate memory for cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Initialize context to perform AES encryption in CTR mode
    EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv, 1);    // Encrypt = 1

    int ciphertextlen;
    // Pass output(ciphertext) and input(plaintext), perform encryption
    EVP_CipherUpdate(ctx, ciphertext, &ciphertextlen, plaintext, plaintextlen);

    // Finalize operation
    EVP_CipherFinal_ex(ctx, ciphertext, &ciphertextlen);
    
    // Free context
    EVP_CIPHER_CTX_free(ctx);
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