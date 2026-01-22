// Alice reads the message from the ”Message.txt” file and the he shared seed from the ”SharedSeed.txt” file. 
// Then the secret key is generated from the shared seed based on utilizing the PRNG function from OpenSSL. The key size must match the message length.
// Then the Hex format of the key is written in a file named “Key.txt”.
// XOR the message with the secret key to obtain the ciphertext: (Ciphertext = Message XOR Key).
// Write the Hex format of the ciphertext in a file named “Ciphertext.txt”.
// Once Bob has processed the message, Alice reads Bob’s computed hash from ”Hash.txt”.
// If the comparison is successful, Alice can be confident that Bob has received the accurate message. She then writes ”Acknowledgment Successful” in a 
    // file called ”Acknowledgment.txt.” Conversely, if the comparison fails, she records ”Acknowledgment Failed.”

#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>

int main() {

    // testing one two
    unsigned char message[] = "Hello, World!";

    return 0;
}