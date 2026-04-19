/*
Description
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "RequiredFunctionsTGDH.c"


int main(int argc, char* argv[]){
    // Arg check
    if(argc != 7) {
        printf("Usage: %s <params_p_file> <params_g_file> <setup_seed_0_file> <setup_seed_1_file> <setup_seed_2_file> <setup_seed_3_file>\n", argv[0]);
        goto free_mem;
    }

    int n = 4;
    int i = 0;

    // Read p and g from files
    BIGNUM *p = get_p(argv[1]);
    if(p == NULL){
        printf("Failed to read param pasdf from file.\n");
        goto free_mem;
    }

    BIGNUM *g = get_g(argv[2]);
    if(g == NULL){
        printf("Failed to read param g from file.\n");
        goto free_mem;
    }

    // Read member seeds and hash to derive secret keys
    unsigned char* buffer;
    int buffer_len = 0;
    unsigned char* secret_keys[4] = {0};

    for(i = 0; i < n; i++){
        buffer = Read_File(argv[3 + i], &buffer_len);
        if(buffer == NULL){
            printf("Failed to read member secret from file.\n");
            goto free_mem;
        }
        secret_keys[i] = malloc(SHA256_DIGEST_LENGTH);
        if(secret_keys[i] == NULL){
            printf("Malloc failed.\n");
            goto free_mem;
        }
        Compute_SHA256(buffer, buffer_len, secret_keys[i]);
        free(buffer);
    }

    // Member secret keys as BIGNUM
    BIGNUM* secret_keys_bn[4] = {0};
    i = bytes_to_bn(secret_keys, secret_keys_bn, n);
    if(i == 0){
        printf("Error in converting secret keys from bytes to BIGNUM.\n");
        goto free_mem;
    }

    BN_CTX* ctx = BN_CTX_new();
    // Member blinded keys
    BIGNUM* blinded_keys[4] = {0};
    i = secret_to_blind(secret_keys_bn, blinded_keys, g, p, n, ctx);
    if(i == 0){
        printf("Error computing blinded keys.\n");
        goto free_mem;
    }

    // Convert BIGNUM keys to key_len-padded byte buffers for the tree
    int key_len = BN_num_bytes(p);
    unsigned char* secret_bytes[4] = {0};
    unsigned char* blinded_bytes[4] = {0};
    for(i = 0; i < n; i++){
        secret_bytes[i] = bn_to_bytes(secret_keys_bn[i], key_len);
        blinded_bytes[i] = bn_to_bytes(blinded_keys[i], key_len);
    }


    // Build tree
    struct Node *root = build_tree(secret_bytes, blinded_bytes, 0, n);

    compute_internal_keys(root, g, p, key_len, ctx);
    
    // Write to file
    if(write_group_key(root, "group_key_setup.txt", key_len) == 0){
        printf("Error writing group key to file.\n");
        goto free_mem;
    }
    
    
    // write_internal_nodes_postorder(root, fp, key_len); //
    
    if(write_blinded_keys(blinded_bytes, n, root, "blinded_keys_setup.txt", key_len) == 0){
        printf("Error writing blinded keys to file.\n");
        goto free_mem;
    }
    free_mem:
    
    free_tree(root);

    return 0;

}

