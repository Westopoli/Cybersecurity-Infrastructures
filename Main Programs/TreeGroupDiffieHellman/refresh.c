/*
Tree-based Group Diffie-Hellman (TGDH) - Refresh Operation

Rotates a single member's leaf secret key without changing group membership.
The targeted member's old leaf secret is replaced by a freshly generated one,
the tree is rebuilt with the same leaf order, and internal keys are re-derived
bottom-up so that the group key changes for forward/backward secrecy:
    sk_internal = (bk_left)^(sk_right) mod p
    bk_internal = g^(sk_internal) mod p

Crypto primitives: OpenSSL BIGNUM modular exponentiation, SHA-256.
DH parameters: RFC 2409 Group 2 (1024-bit MODP), g = 2.

I/O contract:
    Inputs : p, g, current member secrets (hex, multi-line),
             refreshing member's index, that member's new secret (hex).
    Outputs: group_key_refresh.txt, blinded_keys_refresh.txt
*/
#include "RequiredFunctionsTGDH.c"

int main(int argc, char* argv[]){
    // Validate command-line arguments
    if(argc != 6){
        printf("Usage: %s <params_p_file> <params_g_file> <member_secrets_file> <member_index_file> <new_secret_file>\n", argv[0]);
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

    // Load current member leaf secrets (one hex string per line)
    int n = 0;
    BIGNUM **secrets_bn = load_hex_secrets(argv[3], &n);
    if(secrets_bn == NULL){
        printf("Failed to read member secrets.\n");
        return 1;
    }

    // Load the index of the member whose key is being refreshed
    int idx = Read_Int_From_File(argv[4]);
    if(idx < 0 || idx >= n){
        printf("Invalid member index.\n");
        return 1;
    }

    // Swap that member's leaf secret in place with the freshly generated one
    int new_len = 0;
    char *new_hex = Read_File(argv[5], &new_len);
    if(new_hex == NULL){
        printf("Failed to read new secret from file.\n");
        return 1;
    }
    BN_free(secrets_bn[idx]);
    secrets_bn[idx] = hex_to_bn(new_hex);
    free(new_hex);

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

    // Build a balanced binary key tree over the (now refreshed) leaf set
    struct Node *root = build_tree(secret_bytes, blind_bytes, 0, n);
    if(root == NULL){
        printf("Error building tree.\n");
        return 1;
    }

    // Derive internal node secret/blinded keys bottom-up; root secret is the refreshed group key
    compute_internal_keys(root, g, p, key_len, ctx);

    // Emit group key (root secret, hex) and blinded keys (leaves L-to-R + internals post-order)
    write_group_key(root, "group_key_refresh.txt", key_len);
    write_blinded_keys(blind_bytes, n, root, "blinded_keys_refresh.txt", key_len);

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
