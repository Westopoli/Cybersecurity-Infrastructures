/*
Tree-based Group Diffie-Hellman (TGDH) - Leave Operation

Handles a single member departure, shrinking the group from n to n - 1. The
sponsor is the sibling of the departing leaf (even index leaves -> sponsor on
the right, odd index leaves -> sponsor on the left). The sponsor rolls over
its leaf secret so that the leaving party can no longer reconstruct the new
group key, and the tree is rebuilt over the remaining leaves. Internal keys
are re-derived bottom-up:
    sk_internal = (bk_left)^(sk_right) mod p
    bk_internal = g^(sk_internal) mod p

Crypto primitives: OpenSSL BIGNUM modular exponentiation, SHA-256.
DH parameters: RFC 2409 Group 2 (1024-bit MODP), g = 2.

I/O contract:
    Inputs : p, g, current member secrets (hex, multi-line),
             leaving member's index, sponsor's updated secret.
    Outputs: group_key_leave.txt, blinded_keys_leave.txt
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "RequiredFunctionsTGDH.c"

int remove_member(char** members, int leave, int size);

int main(int argc, char* argv[]){
    // Validate command-line arguments
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

    // Load current member secret keys (one hex string per line)
    n = Read_Lines(argv[3], &secret_keys_hex);
    if(n != 4){
        printf("Error reading existing member secrets from file.\n");
        goto free_mem;
    }

    // Load the index of the departing member
    leave_index = Read_Int_From_File(argv[4]);
    if(leave_index == -1){
        printf("Error reading leaving member index.\n");
        goto free_mem;
    }

    // Load the sponsor's rolled-over secret
    sponsor_updated_secret = Read_File(argv[5], &sponsor_updated_secret_len);
    if(sponsor_updated_secret == NULL){
        printf("Failed to read sponsor updated secret from file.\n");
        goto free_mem;
    }

    // Sponsor = sibling of the leaving leaf
    //   even leave_index -> sponsor is the right sibling (leave_index + 1)
    //   odd  leave_index -> sponsor is the left  sibling (leave_index - 1)
    if(leave_index % 2 == 0)
        sponsor_index = leave_index + 1;
    else
        sponsor_index = leave_index - 1;

    // Overwrite the sponsor's leaf secret so the leaving party cannot derive the new group key
    secret_keys_hex[sponsor_index] = Read_File(argv[5], &len);
    if(secret_keys_hex[sponsor_index] == NULL){
        printf("Error reading sponsor secret from file.\n");
        goto free_mem;
    }

    // Drop the leaving leaf from the member array, shrinking the group to n - 1
    n = remove_member(secret_keys_hex, leave_index, n);

    // Lift the remaining leaf secret keys from hex strings into BIGNUM form
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


    // Rebuild the balanced binary key tree over the remaining leaves and derive internal keys
    struct Node *root = build_tree(secret_keys_bytes, blinded_keys_bytes, 0, n);
    compute_internal_keys(root, g, p, key_len, ctx);

    // Emit the new group key (root secret) as hex
    if(write_group_key(root, "group_key_leave.txt", key_len) == 0){
        printf("Error writing group key to file.\n");
        goto free_mem;
    }
    fclose(fp);

    // Emit blinded keys: leaves left-to-right followed by internal nodes in post-order
    if(write_blinded_keys(blinded_keys_bytes, n, root, "blinded_keys_leave.txt", key_len) == 0){
        printf("Error writing blinded keys to file.\n");
        goto free_mem;
    }
    fclose(fp);

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
