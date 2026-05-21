/*
Tree-based Group Diffie-Hellman (TGDH) - Join Operation

Handles a single new-member addition to an existing four-member group, growing
the group from n = 4 to n = 5. The designated sponsor (the rightmost existing
member, whose subtree will be paired with the joiner) rolls over its own leaf
secret, and the new member contributes its own leaf secret. The key tree is
rebuilt over the new five-leaf set and the group key is re-derived bottom-up:
    sk_internal = (bk_left)^(sk_right) mod p
    bk_internal = g^(sk_internal) mod p

Crypto primitives: OpenSSL BIGNUM modular exponentiation, SHA-256.
DH parameters: RFC 2409 Group 2 (1024-bit MODP), g = 2.

I/O contract:
    Inputs : p, g, existing member secrets (hex, multi-line),
             new member secret, sponsor's updated secret.
    Outputs: group_key_join.txt, blinded_keys_join.txt
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "RequiredFunctionsTGDH.c"

BIGNUM* get_g(const char *filename);
BIGNUM* get_p(const char *filename);
int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash);

int main(int argc, char* argv[]){
    // Validate command-line arguments
    if(argc != 6) {
        printf("Usage: %s <params_p_file> <params_g_file> <join_existing_secrets_file> <join_new_secret_file> <join_sponsor_new_secret_file>", argv[0]);
        return 1;
    }

    int n = 5;
    int i = 0;

    int key_len = 0;
    BN_CTX* ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;

    char** secret_keys_hex = NULL;
    BIGNUM** secret_keys_bn = NULL;
    BIGNUM** blinded_keys_bn = NULL;
    unsigned char** secret_keys_bytes = NULL;
    unsigned char** blinded_keys_bytes = NULL;

    int new_member_secret_len = 0;
    unsigned char* new_member_secret = NULL;
    int sponsor_updated_secret_len = 0;
    unsigned char* sponsor_updated_secret = NULL;
    
    FILE* fp = NULL;

    // Load DH parameters p and g from disk
    p = get_p(argv[1]);
    if(p == NULL){
        printf("Failed to read param p from file.\n");
        goto free_mem;
    }

    g = get_g(argv[2]);
    if(g == NULL){
        printf("Failed to read param g from file.\n");
        goto free_mem;
    }

    // Load existing four-member secret keys (one hex string per line)
    if(Read_Lines(argv[3], &secret_keys_hex) != 4){
        printf("Error reading existing member secrets from file.\n");
        goto free_mem;
    }

    // Load the joining member's leaf secret and the sponsor's rolled-over secret
    new_member_secret = Read_File(argv[4], &new_member_secret_len);
    if(new_member_secret == NULL){
        printf("Failed to read new member secret from file.\n");
        goto free_mem;
    }

    sponsor_updated_secret = Read_File(argv[5], &sponsor_updated_secret_len);
    if(sponsor_updated_secret == NULL){
        printf("Failed to read sponsor updated secret from file.\n");
        goto free_mem;
    }

    // Sponsor (rightmost existing leaf) refreshes its own secret
    secret_keys_hex[3] = sponsor_updated_secret;

    // Append the new member as the rightmost leaf, growing the group to n = 5
    secret_keys_hex[4] = new_member_secret;


    // Lift leaf secret keys from hex strings into BIGNUM form
    secret_keys_bn = malloc(n * sizeof(BIGNUM*));
    for(i = 0; i < n; i++){
        secret_keys_bn[i] = hex_to_bn(secret_keys_hex[i]);
        if(secret_keys_bn[i] == NULL){
            printf("Error in converting secret keys from hex to BIGNUM.\n");
            goto free_mem;
        }
    }

    // Compute leaf blinded keys: bk_i = g^sk_i mod p
    blinded_keys_bn = malloc(n * sizeof(BIGNUM*));
    ctx = BN_CTX_new();
    i = secret_to_blind(secret_keys_bn, blinded_keys_bn, g, p, n, ctx);
    if(i == 0){
        printf("Error computing blinded keys.\n");
        goto free_mem;
    }

    // Pack BIGNUM keys into fixed-width (key_len) big-endian buffers owned by the tree
    key_len = BN_num_bytes(p);
    secret_keys_bytes = malloc(n * sizeof(unsigned char*));
    blinded_keys_bytes = malloc(n * sizeof(unsigned char*));
    for(i = 0; i < n; i++){
        secret_keys_bytes[i] = bn_to_bytes(secret_keys_bn[i], key_len);
        blinded_keys_bytes[i] = bn_to_bytes(blinded_keys_bn[i], key_len);
    }


    // Rebuild the balanced binary key tree over the new five-leaf set and derive internal keys
    struct Node *root = build_tree(secret_keys_bytes, blinded_keys_bytes, 0, n);
    compute_internal_keys(root, g, p, key_len, ctx);

    // Emit the new group key (root secret) as hex
    if(write_group_key(root, "group_key_join.txt", key_len) == 0){
        printf("Error writing group key to file.\n");
        goto free_mem;
    }
    fclose(fp);

    // Emit blinded keys: leaves left-to-right followed by internal nodes in post-order
    if(write_blinded_keys(blinded_keys_bytes, n, root, "blinded_keys_join.txt", key_len) == 0){
        printf("Error writing blinded keys to file.\n");
        goto free_mem;
    }
    fclose(fp);

    free_mem:
    free_tree(root);

    return 0;
}

