/*
- Read DH parameters
- Read existing member secrets from a multi-line file (hex, one secret per line).
- Read the new member’s secret and the sponsor’s updated secret from files (hex).
- Replace the last existing member’s secret (the sponsor) with the sponsor’s new secret.
- Append the new member’s secret.
- Rebuild the tree and compute the new group key.
- Write “group key join.txt” and “blinded keys join.txt”
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
    // Arg check
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

    /* Read p and g from files */
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
    
    /*Read existing member secrets from a multi-line file*/
    if(Read_Lines(argv[3], &secret_keys_hex) != 4){
        printf("Error reading existing member secrets from file.\n");
        goto free_mem;
    }

    /*Read the new member’s secret and the sponsor’s updated secret from files*/
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
    
    /*Replace the last existing member’s secret with the sponsor’s new secret*/
    secret_keys_hex[3] = sponsor_updated_secret;
    
    /*Append the new member’s secret*/
    secret_keys_hex[4] = new_member_secret;


    /*Key calculation*/
    // Secret keys: hex -> BIGNUM
    secret_keys_bn = malloc(n * sizeof(BIGNUM*));
    for(i = 0; i < n; i++){
        secret_keys_bn[i] = hex_to_bn(secret_keys_hex[i]);
        if(secret_keys_bn[i] == NULL){
            printf("Error in converting secret keys from hex to BIGNUM.\n");
            goto free_mem;
        }
    }
    
    // Calculate blind keys (BIGNUM)
    blinded_keys_bn = malloc(n * sizeof(BIGNUM*));
    ctx = BN_CTX_new();
    i = secret_to_blind(secret_keys_bn, blinded_keys_bn, g, p, n, ctx);
    if(i == 0){
        printf("Error computing blinded keys.\n");
        goto free_mem;
    }
    
    // Keys: BIGNUM -> bytes
    key_len = BN_num_bytes(p);
    secret_keys_bytes = malloc(n * sizeof(unsigned char*));
    blinded_keys_bytes = malloc(n * sizeof(unsigned char*));
    for(i = 0; i < n; i++){
        secret_keys_bytes[i] = bn_to_bytes(secret_keys_bn[i], key_len);
        blinded_keys_bytes[i] = bn_to_bytes(blinded_keys_bn[i], key_len);
    }

    
    /*Build TGDH tree*/
    struct Node *root = build_tree(secret_keys_bytes, blinded_keys_bytes, 0, n);
    compute_internal_keys(root, g, p, key_len, ctx);

    /*Write group key to file*/
    if(write_group_key(root, "group_key_join.txt", key_len) == 0){
        printf("Error writing group key to file.\n");
        goto free_mem;
    }
    fclose(fp);

    /*Write blinded keys to file*/
    if(write_blinded_keys(blinded_keys_bytes, n, root, "blinded_keys_join.txt", key_len) == 0){
        printf("Error writing blinded keys to file.\n");
        goto free_mem;
    }
    fclose(fp);

    /*Free memory*/
    free_mem:
    free_tree(root);

    return 0;
}   

