/*
Description
*/

#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/evp.h>


/* Function declarations*/
// Fully implemented functions
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
int Encrypt_AES(const unsigned char* plaintext, int plaintextlen, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);


// Still need implementation
    // Hash SHA256
    // HMAC


int main(int argc, char *argv[]) {
    
    unsigned char IV[16] = "abcdefghijklmnop";

    // Initialize keys var
    // Initialize ciphertexts var
    // Initialize individualHMACs var

    // Read shared seed argv[2]
    // Use PRNG on seed, get key
    
    // Initialize HMAC_curr and HMAC_prev with NULL
    // Open message file argv[1]
    // Read first message
    // Until the end of the file is reached
        // Concatenate key to keys var
        // AES encrypt message
        // Concatenate to cipherexts var
        // Compute HMAC_curr w/ key and ciphertext
        // Concatenate to individualHMAC var
        // Append/concat HMAC_curr to HMAC_prev
        // Hash the key to get next key


    // Convert keys to hex, write to "Keys.txt"
    // Convert ciphertexts to hex, write to "Ciphertexts.txt"
    // Convert individualHMACs to hex, write to "IndividualHMAC.txt"
    // Convert HMAC_curr (HMAC aggregate)to hex, write to "AggregatedHMAC.txt"


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
	fgets(output, temp_size, pFile);
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

int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}
