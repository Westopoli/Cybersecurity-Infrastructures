/*
Tree-based Group Diffie-Hellman (TGDH) - Merge Operation

Combines two independent groups into a single larger group. The leaf secret
keys of both groups are concatenated (group1 first, group2 appended), and a
fresh balanced binary key tree is built over the combined leaf set. Internal
keys are derived bottom-up so that the resulting root secret is shared by
every member of the merged group:
    sk_internal = (bk_left)^(sk_right) mod p
    bk_internal = g^(sk_internal) mod p

Crypto primitives: OpenSSL BIGNUM modular exponentiation, SHA-256.
DH parameters: RFC 2409 Group 2 (1024-bit MODP), g = 2.

I/O contract:
    Inputs : p, g, group1 leaf secrets (hex, multi-line),
             group2 leaf secrets (hex, multi-line).
    Outputs: group_key_merge.txt, blinded_keys_merge.txt
*/
#include "RequiredFunctionsTGDH.c"

int main(int argc, char* argv[]){
    // Validate command-line arguments
    if(argc != 5){
        printf("Usage: %s <params_p_file> <params_g_file> <group1_secrets_file> <group2_secrets_file>\n", argv[0]);
        return 1;
    }

    int i;

    // Load DH parameters p and g from disk
    BIGNUM *p = get_p(argv[1]);
    if(p == NULL){
        printf("Failed to read param p from file.\n");
        return 1;
    }

    BIGNUM *g = get_g(argv[2]);
    if(g == NULL){
        printf("Failed to read param g from file.\n");
        return 1;
    }

    // Load both groups' leaf secrets and concatenate them into a single n = n1 + n2 array
    int n1 = 0, n2 = 0;
    BIGNUM **secrets1 = load_hex_secrets(argv[3], &n1);
    if(secrets1 == NULL){
        printf("Failed to read group 1 secrets.\n");
        return 1;
    }

    BIGNUM **secrets2 = load_hex_secrets(argv[4], &n2);
    if(secrets2 == NULL){
        printf("Failed to read group 2 secrets.\n");
        return 1;
    }

    int n = n1 + n2;
    BIGNUM **secrets_bn = malloc(n * sizeof(BIGNUM*));
    if(secrets_bn == NULL){
        printf("Malloc failed.\n");
        return 1;
    }
    for(i = 0; i < n1; i++) secrets_bn[i] = secrets1[i];
    for(i = 0; i < n2; i++) secrets_bn[n1 + i] = secrets2[i];
    free(secrets1);
    free(secrets2);

    BN_CTX *ctx = BN_CTX_new();

    // Compute leaf blinded keys: bk_i = g^sk_i mod p
    BIGNUM **blinded_keys_bn = malloc(n * sizeof(BIGNUM*));
    if(blinded_keys_bn == NULL){
        printf("Malloc failed.\n");
        return 1;
    }
    i = secret_to_blind(secrets_bn, blinded_keys_bn, g, p, n, ctx);
    if(i == 0){
        printf("Error computing blinded keys.\n");
        return 1;
    }

    // Pack BIGNUM keys into fixed-width (key_len) big-endian buffers owned by the tree
    int key_len = BN_num_bytes(p);
    unsigned char **secret_bytes = malloc(n * sizeof(unsigned char*));
    unsigned char **blind_bytes = malloc(n * sizeof(unsigned char*));
    if(secret_bytes == NULL || blind_bytes == NULL){
        printf("Malloc failed.\n");
        return 1;
    }
    for(i = 0; i < n; i++){
        secret_bytes[i] = bn_to_bytes(secrets_bn[i], key_len);
        blind_bytes[i] = bn_to_bytes(blinded_keys_bn[i], key_len);
        BN_free(secrets_bn[i]);
        BN_free(blinded_keys_bn[i]);
    }
    free(secrets_bn);
    free(blinded_keys_bn);

    // Build a balanced binary key tree over the combined leaf set
    struct Node *root = build_tree(secret_bytes, blind_bytes, 0, n);
    if(root == NULL){
        printf("Error building tree.\n");
        return 1;
    }

    // Derive internal node secret/blinded keys bottom-up; root secret is the merged group key
    compute_internal_keys(root, g, p, key_len, ctx);

    // Emit group key (root secret, hex) and blinded keys (leaves L-to-R + internals post-order)
    write_group_key(root, "group_key_merge.txt", key_len);
    write_blinded_keys(blind_bytes, n, root, "blinded_keys_merge.txt", key_len);

    // Null out leaf buffer pointers so free_tree() (which owns them now) doesn't double-free
    for(i = 0; i < n; i++){
        secret_bytes[i] = NULL;
        blind_bytes[i] = NULL;
    }
    free(secret_bytes);
    free(blind_bytes);
    free_tree(root);
    BN_free(g);
    BN_free(p);
    BN_CTX_free(ctx);

    return 0;
}
