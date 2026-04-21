#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "RequiredFunctionsTGDH.c"

int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash);
BIGNUM* get_g(const char *filename);
BIGNUM* get_p(const char *filename);
int bytes_to_bn(unsigned char* strings[], BIGNUM* bns[], int n);
int secret_to_blind(BIGNUM* secrets[], BIGNUM* blinds[], BIGNUM* g, BIGNUM* p, int n, BN_CTX* ctx);
unsigned char* bn_to_bytes(BIGNUM *bn, int key_len);
struct Node* build_TGDH(unsigned char** secrets, unsigned char** blinds, int start, int end, int n);

struct Node {
    unsigned char* secret_key;
    unsigned char* blinded_key;

    struct Node *parent;
    struct Node *left;
    struct Node *right;
};


int main(int argc, char* argv[]){
    // Arg check
    if(argc != 7) {
        printf("Usage: %s <params_p_file> <params_g_file> <setup_seed_0_file> <setup_seed_1_file> <setup_seed_2_file> <setup_seed_3_file>\n", argv[0]);
        return 1;
    }

    int n = 4;
    int i = 0;

    // Read p and g from files
    BIGNUM *p = get_p(argv[1]);
    if(p == NULL){
        printf("Failed to read param p from file.\n");
    }

    BIGNUM *g = get_g(argv[2]);
    if(g == NULL){
        printf("Failed to read param g from file.\n");
    }

    // Read member seeds and hash to derive secret keys
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

    // Member secret keys as BIGNUM
    BIGNUM* secret_keys_bn[4] = {0};
    i = bytes_to_bn(secret_keys, secret_keys_bn, n);
    if(i == 0){
        printf("Error in converting secret keys from bytes to BIGNUM.\n");
        return 1;
    }

    BN_CTX* ctx = BN_CTX_new();
    // Member blinded keys
    BIGNUM* blinded_keys[4] = {0};
    i = secret_to_blind(secret_keys_bn, blinded_keys, g, p, n, ctx);
    if(i == 0){
        printf("Error computing blinded keys.\n");
        return 1;
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
    struct Node *root = build_TGDH(secret_bytes, blinded_bytes, 0, n - 1, n);

}

// SHA256 hash
int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return 0;
}

// Build TGDH left-heavy splitting balanced tree
struct Node* build_TGDH(unsigned char** secrets, unsigned char** blinds, int start, int end, int n){

    struct Node *a = malloc(sizeof(struct Node));
    if(a == NULL){
        return NULL;
    }

    a->parent = NULL;
    a->left = NULL;
    a->right = NULL;

    // Base case
    if(n == 1){
        a->secret_key = secrets[start];
        a->blinded_key = blinds[start];
        return a;
    }

    int left_n = (n + 1) / 2;
    int right_n = n / 2;

    struct Node *left = build_TGDH(secrets, blinds, start, start + left_n - 1, left_n);
    struct Node *right = build_TGDH(secrets, blinds, start + left_n, end, right_n);

    a->left = left;
    a->right = right;
    left->parent = a;
    right->parent = a;

    return a;
}

unsigned char* bn_to_bytes(BIGNUM *bn, int key_len){
    unsigned char *buf = calloc(key_len, 1);
    if(buf == NULL) return NULL;
    int actual_len = BN_num_bytes(bn);
    BN_bn2bin(bn, buf + (key_len - actual_len));
    return buf;
}

BIGNUM* get_g(const char *filename){
    // Read g from file as int
    int g_int = Read_Int_From_File(filename);
    if(g_int == -1){
        return NULL;
    }

    BIGNUM* g = BN_new();
    if(g == NULL){
        return NULL;
    }

    // Convert g from int to BIGNUM
    int i = BN_set_word(g, g_int);
    if(i == 0){
        return NULL;
    }
    return g;
}

BIGNUM* get_p(const char *filename){
    // Read p from file as string
    int p_len = 0;
    char* p_string = Read_File(filename, &p_len);
    if(p_string == NULL){
        return NULL;
    }

    BIGNUM* p = NULL;

    // Convert p from string to BIGNUM
    int i = BN_hex2bn(&p, p_string);
    if(i == 0){
        return NULL;
    }
    return p;
}

int bytes_to_bn(unsigned char* strings[], BIGNUM* bns[], int n){
    int i;
    for(i = 0; i < n; i++){
        bns[i] = BN_bin2bn(strings[i], SHA256_DIGEST_LENGTH, NULL);
        if(bns[i] == NULL){
            return 0;
        }
    }
    return 1;
}

int secret_to_blind(BIGNUM* secrets[], BIGNUM* blinds[], BIGNUM* g, BIGNUM* p, int n, BN_CTX* ctx){
    int i;
    for(i = 0; i < n; i++){
        blinds[i] = BN_new();
        if(BN_mod_exp(blinds[i], g, secrets[i], p, ctx) == 0){
            return 0;
        }
    }
    return 1;
}
