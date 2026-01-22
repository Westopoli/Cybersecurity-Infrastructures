
#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>

int main() {

    unsigned char data[] = "Hello, World!";

    // important to use unsigned
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(data, sizeof(data), hash);

    // prints the hash in machine code (unreadable)
    printf("SHA-256 hash: %s", hash);

    // prints the hash in hexadecimal (readable)
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }

    // for homeowork 1
    // save ciphertext to file when computed

    return 0;
}