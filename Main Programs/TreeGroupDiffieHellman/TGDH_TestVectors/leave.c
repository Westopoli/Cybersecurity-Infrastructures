/*
- Read DH parameters.
- Read all current member secrets (hex, one per line).
- Read the index of the leaving member and the sponsor’s new secret.
- Determine the sponsor (sibling of the leaving member).
- Remove the leaving member, update the sponsor’s secret.
- Rebuild the tree with n − 1 members and compute the new group key.
-Write “group key leave.txt” and “blinded keys leave.txt”
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "RequiredFunctionsTGDH.c"

int remove_member(char** members, int leave, int size);

int main(int argc, char* argv[]){
    // Arg check
    if(argc != 6) {
        printf("Usage: %s <params_p_file> <params_g_file> <leave_member_secrets_file> <leave_leaving_index_file> <leave_sponsor_new_secret_file>", argv[0]);
        return 1;
    }

    int n = 0;
    int i = 0;
    int len = 0;
    int key_len = 0;

    BN_CTX* ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;

    char** secret_keys_hex = NULL;
    BIGNUM** secret_keys_bn = NULL;
    BIGNUM** blinded_keys_bn = NULL;
    unsigned char** secret_keys_bytes = NULL;
    unsigned char** blinded_keys_bytes = NULL;

    int leave_index = -1;
    int sponsor_index = -1;

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

    /*Read current member secrets from a multi-line file*/
    n = Read_Lines(argv[3], &secret_keys_hex);
    if(n != 4){
        printf("Error reading existing member secrets from file.\n");
        goto free_mem;
    }

    /*Read index of leaving member*/
    leave_index = Read_Int_From_File(argv[4]);
    if(leave_index == -1){
        printf("Error reading leaving member index.\n");
        goto free_mem;
    }

    /*Read sponsor's new secret*/
    sponsor_updated_secret = Read_File(argv[5], &sponsor_updated_secret_len);
    if(sponsor_updated_secret == NULL){
        printf("Failed to read sponsor updated secret from file.\n");
        goto free_mem;
    }

    /*Determine sponsor index and update its secret*/
    // Leave even -> sponsor is to the right
    // Leave odd  -> sponsor is to the left 
    if(leave_index % 2 == 0)
        sponsor_index = leave_index + 1;
    else
        sponsor_index = leave_index - 1;

    secret_keys_hex[sponsor_index] = Read_File(argv[5], &len); 
    if(secret_keys_hex[sponsor_index] == NULL){
        printf("Error reading sponsor secret from file.\n");
        goto free_mem;
    }

    /*Remove the leaving member*/
    n = remove_member(secret_keys_hex, leave_index, n);
    
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
    if(write_group_key(root, "group_key_leave.txt", key_len) == 0){
        printf("Error writing group key to file.\n");
        goto free_mem;
    }
    fclose(fp);

    /*Write blinded keys to file*/
    if(write_blinded_keys(blinded_keys_bytes, n, root, "blinded_keys_leave.txt", key_len) == 0){
        printf("Error writing blinded keys to file.\n");
        goto free_mem;
    }
    fclose(fp);

    /*Free memory*/
    free_mem:
    free_tree(root);

    return 0;
}   

int remove_member(char** members, int leave, int size){
    if(leave >= size)
        return 0;
        
    free(members[leave]);
    for(int i = leave; i < size - 1; i++){
        members[i] = members[i + 1];
    }
    members[size - 1] = NULL;
        
    return size - 1;
}
