// Bob reads the ciphertext from the ”Ciphertext.txt” file.
// Read the shared seed from the ”SharedSeed.txt” file. 
// Generate the secret key from the shared seed based on utilizing the PRNG function from OpenSSL. The key size must match the message length.
// XOR the received ciphertext with the secret key to obtain the plaintext: (plaintext = ciphertext XOR key).
// Write the decrypted plaintext in a file named “Plaintext.txt”.
// Hash the plaintext via SHA256 and writes the Hex format of the hash in a file named ”Hash.txt” for Alice to verify

#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>

int main() {

    unsigned char message[] = "Hello, World!";

    return 0;
}