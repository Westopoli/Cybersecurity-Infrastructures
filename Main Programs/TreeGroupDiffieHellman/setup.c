/*
Tree-based Group Diffie-Hellman (TGDH) - Setup Operation

Performs the initial group key agreement for a fixed group of four members.
Each member contributes a raw seed; SHA-256 of the seed yields that member's
leaf secret key (sk_i). Leaf blinded keys are computed as bk_i = g^sk_i mod p.
A balanced binary key tree is built over the leaves, and internal node keys
are derived bottom-up via the TGDH recurrence:
    sk_internal  = (bk_left)^(sk_right) mod p
    bk_internal  = g^(sk_internal) mod p
The root secret_key is the shared group key.

Crypto primitives: OpenSSL BIGNUM modular exponentiation, SHA-256.
DH parameters: RFC 2409 Group 2 (1024-bit MODP), g = 2.

I/O contract:
    Inputs : p (hex), g (decimal), and four member seed files.
    Outputs: group_key_setup.txt    (root secret key, hex)
             blinded_keys_setup.txt (leaf blinded keys + internal blinded keys, post-order)
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "RequiredFunctionsTGDH.c"


int main(int argc, char* argv[]){
    // Validate command-line arguments
    if(argc != 7) {
        printf("Usage: %s <params_p_file> <params_g_file> <setup_seed_0_file> <setup_seed_1_file> <setup_seed_2_file> <setup_seed_3_file>\n", argv[0]);
        return 1;
    }

    int n = 4;
    int i = 0;

    // Load DH parameters p and g from disk
    BIGNUM *p = get_p(argv[1]);
    if(p == NULL){
        printf("Failed to read param p from file.\n");
    }

    BIGNUM *g = get_g(argv[2]);
    if(g == NULL){
        printf("Failed to read param g from file.\n");
    }

    // Derive each member's leaf secret key as sk_i = SHA-256(seed_i)
    unsigned char* buffer;
    int buffer_len = 0;
    unsigned char* secret_keys[4] = {0};

    for(i = 0; i < n; i++){
        buffer = Read_File(argv[3 + i], &buffer_len);
        if(buffer == NULL){
            printf("Failed to read member secret from file.\n");
            return 1;
        }
        secret_keys[i] = malloc(SHA256_DIGEST_LENGTH);
        if(secret_keys[i] == NULL){
            printf("Malloc failed.\n");
            return 1;
        }
        Compute_SHA256(buffer, buffer_len, secret_keys[i]);
        free(buffer);
    }

    // Lift leaf secret keys from raw bytes into BIGNUM form
    BIGNUM* secret_keys_bn[4] = {0};
    i = bytes_to_bn(secret_keys, secret_keys_bn, n);
    if(i == 0){
        printf("Error in converting secret keys from bytes to BIGNUM.\n");
        return 1;
    }

    BN_CTX* ctx = BN_CTX_new();
    // Compute leaf blinded keys: bk_i = g^sk_i mod p
    BIGNUM* blinded_keys[4] = {0};
    i = secret_to_blind(secret_keys_bn, blinded_keys, g, p, n, ctx);
    if(i == 0){
        printf("Error computing blinded keys.\n");
        return 1;
    }

    // Pack BIGNUM keys into fixed-width (key_len) big-endian buffers owned by the tree
    int key_len = BN_num_bytes(p);
    unsigned char* secret_bytes[4] = {0};
    unsigned char* blinded_bytes[4] = {0};
    for(i = 0; i < n; i++){
        secret_bytes[i] = bn_to_bytes(secret_keys_bn[i], key_len);
        blinded_bytes[i] = bn_to_bytes(blinded_keys[i], key_len);
    }

    // Pack BIGNUM keys into fixed-width (key_len) big-endian buffers owned by the tree
    int key_len = BN_num_bytes(p);
    unsigned char* secret_bytes[4] = {0};
    unsigned char* blinded_bytes[4] = {0};
    for(i = 0; i < n; i++){
        secret_bytes[i] = bn_to_bytes(secret_keys_bn[i], key_len);
        blinded_bytes[i] = bn_to_bytes(blinded_keys[i], key_len);
    }

    // Build a balanced binary key tree over the four leaves
    struct Node *root = build_tree(secret_bytes, blinded_bytes, 0, n);

    // Derive internal node secret/blinded keys bottom-up; root secret is the group key
    compute_internal_keys(root, g, p, key_len, ctx);

    // Emit root secret key (the shared group key) as hex
    if(write_group_key(root, "group_key_setup.txt", key_len) == 0){
        printf("Error writing group key to file.\n");
        goto free_mem;
    }

    // Emit blinded keys: leaves left-to-right followed by internal nodes in post-order
    if(write_blinded_keys(blinded_bytes, n, root, "blinded_keys_setup.txt", key_len) == 0){
        printf("Error writing blinded keys to file.\n");
        goto free_mem;
    }
    free_mem:

    free_tree(root);

    return 0;

}

