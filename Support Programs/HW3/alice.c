/*
Forward-Secure and Aggregate Digital Forensics Tools

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
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_MESSAGES 100
#define MAX_MESSAGE_LENGTH 1025
#define KEY_LENGTH 32

/* Function declarations*/
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
int Encrypt_AES(const unsigned char* plaintext, int plaintextlen, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);

// Struct to encapsulate message data
struct MessageInfo {
    unsigned char plainText[MAX_MESSAGE_LENGTH];
    int plainTextLen;
    unsigned char cipherText[MAX_MESSAGE_LENGTH];
    int cipherTextLen;
    unsigned char key[KEY_LENGTH];
    int keyLen;
};

int main(int argc, char *argv[]) {
    
    unsigned char IV[16] = "abcdefghijklmnop";

    // if(argc != 2) {
    //     printf("Incorrect number of arguments.\n");
    //     return 1;
    // }

    // Reads shared seed/messages from file
    unsigned char* messagesAll = malloc(MAX_MESSAGES * MAX_MESSAGE_LENGTH);
    int len;
    messagesAll = Read_File(argv[1], &len);
    int numMessages = len / MAX_MESSAGE_LENGTH;

// Initial loop implementation, didn't work correctly
    // // loop through numMessages and seperate them int individual messages by newline character, store them in an array of Messages struct
    // struct MessageInfo messages[MAX_MESSAGES];
    // for (int i = 0; i < numMessages; i++) {
    //     unsigned char* singleMessage = malloc(MAX_MESSAGE_LENGTH);
    //     memcpy(singleMessage, messagesAll + (i * MAX_MESSAGE_LENGTH), MAX_MESSAGE_LENGTH);
    //     // printf("Raw message \n %d: %s\n\n", i+1, singleMessage);
    //     memcpy(messages[i].plainText, singleMessage, MAX_MESSAGE_LENGTH);
    //     // printf("Message \n %d: %s\n", i+1, messages[i].plainText);
    //     messages[i].plainTextLen = strlen((char*)singleMessage);
    //     free(singleMessage);
    //     // printf("Iteration %d: Message length: %d\n", i+1, messages[i].plainTextLen);
    // }

    struct MessageInfo messages[MAX_MESSAGES];
    int currentPos = 0;
    int i = 0;
    int currentMessage = 0;

    // Loop through each individual message till newline character reached, store information about location, copy message to struct
    while (i < len && currentMessage < MAX_MESSAGES) {
        // printf("cur mess: %d < max mess: %d\n", currentMessage, MAX_MESSAGES);
        // printf("cur pos: %d < len: %d\n", i, len);
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
        // printf("messageLen: %d\n", messageLen);
        
        // Copy the message by calculating the offset from start
        // currentPos is the start of the message, i is the end
        currentPos = i - messageLen;
        memcpy(messages[currentMessage].plainText, messagesAll + currentPos, messageLen);
        // printf("Message copied: %s\n", messages[currentMessage].plainText);
        // printf("Message number: %d\n", currentMessage);
        messages[currentMessage].plainTextLen = messageLen;
        
        // Message has been copied, i moves past newline, currentMessage increments
        i++; 
        currentMessage++;
    }

    // Uses PRNG to create initial symmetric key
    // NEXT STEP ---------

    
    free(messagesAll);
    
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