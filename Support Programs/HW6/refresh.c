#include "tgdh_shared.c"

int main(int argc, char* argv[]){
    // Arg check
    if(argc != 6){
        printf("Usage: %s <params_p_file> <params_g_file> <member_secrets_file> <member_index_file> <new_secret_file>\n", argv[0]);
        return 1;
    }

    int i;

    // Load p and g
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

    // Read all current member secrets 
    int n = 0;
    BIGNUM **secrets_bn = load_hex_secrets(argv[3], &n);
    if(secrets_bn == NULL){
        printf("Failed to read member secrets.\n");
        return 1;
    }

    // Read the refreshing members index 
    int idx = Read_Int_From_File(argv[4]);
    if(idx < 0 || idx >= n){
        printf("Invalid member index.\n");
        return 1;
    }

    // Replace the refreshing members secret with the new one 
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

    // Compute leaf blinded keys 
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

    // Convert BIGNUM keys to byte buffers for the tree
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

    // Build tree 
    struct Node *root = build_tree(secret_bytes, blind_bytes, 0, n);
    if(root == NULL){
        printf("Error building tree.\n");
        return 1;
    }

    // Compute internal node keys 
    compute_internal_keys(root, g, p, key_len, ctx);

    // Output group key and blinded keys
    write_group_key(root, "group_key_refresh.txt", key_len);
    write_blinded_keys(blind_bytes, n, root, "blinded_keys_refresh.txt", key_len);

    // Free memory, NULL out arrays so free_tree owns all byte buffers
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
