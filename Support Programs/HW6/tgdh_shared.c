// TGDH Shared Library
// Helper functions used by setup.c, merge.c, refresh.c (West)
// and join.c, leave.c (Daniel)
//
// The tree owns all key byte buffers.
// After build_tree() returns, the caller should NULL out its secret_bytes[]
// and blind_bytes[] array entries so that free_tree() handles all cleanup
// with no double-free
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "RequiredFunctionsTGDH.c"

struct Node {
    unsigned char *secret_key;
    unsigned char *blinded_key;

    struct Node *parent;
    struct Node *left;
    struct Node *right;
};

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
    if(BN_set_word(g, g_int) == 0){
        BN_free(g);
        return NULL;
    }
    return g;
}

BIGNUM* get_p(const char *filename){
    // Read p from file as hex string
    int p_len = 0;
    char* p_string = Read_File(filename, &p_len);
    if(p_string == NULL){
        return NULL;
    }

    BIGNUM* p = NULL;

    // Convert p from hex string to BIGNUM
    if(BN_hex2bn(&p, p_string) == 0){
        free(p_string);
        return NULL;
    }
    free(p_string);
    return p;
}

// hex string -> BIGNUM
BIGNUM* hex_to_bn(const char *hex_string){
    // BN_hex2bn allocates the BIGNUM when the input pointer is NULL
    BIGNUM *bn = NULL;
    if(BN_hex2bn(&bn, hex_string) == 0){
        return NULL;
    }
    return bn;
}

// raw SHA-256 byte arrays -> BIGNUM array 
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

// read all hex secrets from a file, return BIGNUM array
BIGNUM** load_hex_secrets(const char *filename, int *n_out){
    char **lines = NULL;
    int n = Read_Lines(filename, &lines);
    if(n == 0) return NULL;

    BIGNUM **bns = malloc(n * sizeof(BIGNUM*));
    if(bns == NULL) return NULL;

    for(int i = 0; i < n; i++){
        bns[i] = hex_to_bn(lines[i]);
        free(lines[i]);
    }
    free(lines);

    *n_out = n;
    return bns;
}

int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    return 1;
}

// Compute blinds[i] = g^secrets[i] mod p for each leaf i
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

// Convert a BIGNUM to a zero-padded big-endian byte buffer
// The caller owns the returned buffer and must free() it
unsigned char* bn_to_bytes(BIGNUM *bn, int key_len){
    unsigned char *buf = calloc(key_len, 1);
    if(buf == NULL) return NULL;
    int actual_len = BN_num_bytes(bn);
    // Right-align so the number is in the low bytes (big-endian with leading zeros)
    BN_bn2bin(bn, buf + (key_len - actual_len));
    return buf;
}

// Recursively build a left-heavy balanced binary tree over leaves
// secret_bytes[start - start+n-1] and blind_bytes[start - start+n-1
// Internal nodes have secret_key = blinded_key = NULL (filled by compute_internal_keys)
struct Node* build_tree(unsigned char **secret_bytes, unsigned char **blind_bytes, int start, int n){
    struct Node *node = malloc(sizeof(struct Node));
    if(node == NULL) return NULL;

    node->parent = NULL;
    node->left = NULL;
    node->right = NULL;

    if(n == 1){
        // Leaf takes ownership of the byte buffer pointers
        node->secret_key = secret_bytes[start];
        node->blinded_key = blind_bytes[start];
        return node;
    }

    int left_n = (n + 1) / 2;
    int right_n = n / 2;         

    node->left = build_tree(secret_bytes, blind_bytes, start, left_n);
    node->right = build_tree(secret_bytes, blind_bytes, start + left_n, right_n);
    node->left->parent = node;
    node->right->parent = node;
    node->secret_key = NULL;
    node->blinded_key = NULL;

    return node;
}

// Post-order walk 
//   secret_key  = BK_left ^ K_right  mod p   (stored as key_len bytes)
//   blinded_key = g ^ secret_key     mod p   (stored as key_len bytes)
void compute_internal_keys(struct Node *node, BIGNUM *g, BIGNUM *p, int key_len, BN_CTX *ctx){
    if(node->left == NULL) return;  // leaf, already filled

    compute_internal_keys(node->left, g, p, key_len, ctx);
    compute_internal_keys(node->right, g, p, key_len, ctx);

    // Load child keys as BIGNUMs for exponentiation
    BIGNUM *bk_left = BN_bin2bn(node->left->blinded_key, key_len, NULL);
    BIGNUM *k_right = BN_bin2bn(node->right->secret_key, key_len, NULL);

    // secret_key = BK_left ^ K_right mod p
    BIGNUM *sk = BN_new();
    BN_mod_exp(sk, bk_left, k_right, p, ctx);
    node->secret_key = bn_to_bytes(sk, key_len);

    // blinded_key = g ^ secret_key mod p
    BIGNUM *bk = BN_new();
    BN_mod_exp(bk, g, sk, p, ctx);
    node->blinded_key = bn_to_bytes(bk, key_len);

    BN_free(bk_left);
    BN_free(k_right);
    BN_free(sk);
    BN_free(bk);
}

// Write root->secret_key as an uppercase hex string (+ newline) to filename
// Uses BN_bn2hex for canonical output (no artificial leading zeros)
int write_group_key(struct Node *root, const char *filename, int key_len){
    BIGNUM *sk = BN_bin2bn(root->secret_key, key_len, NULL);
    if(sk == NULL) return 0;

    char *hex = BN_bn2hex(sk);
    BN_free(sk);
    if(hex == NULL) return 0;

    FILE *fp = fopen(filename, "w");
    if(fp == NULL){
        OPENSSL_free(hex);
        return 0;
    }
    fprintf(fp, "%s\n", hex);
    fclose(fp);
    OPENSSL_free(hex);
    return 1;
}

// print blinded key for each internal node only.
static void write_internal_nodes_postorder(struct Node *node, FILE *fp, int key_len){
    if(node->left == NULL) return;  // leaf, skip
    write_internal_nodes_postorder(node->left, fp, key_len);
    write_internal_nodes_postorder(node->right, fp, key_len);

    BIGNUM *bk = BN_bin2bn(node->blinded_key, key_len, NULL);
    char *hex = BN_bn2hex(bk);
    fprintf(fp, "%s\n", hex);
    OPENSSL_free(hex);
    BN_free(bk);
}

// Write blinded keys to filename
//   leaves left-to-right first (from the leaf_blinds byte array)
//   internal nodes in post-order
int write_blinded_keys(unsigned char **leaf_blinds, int n, struct Node *root, const char *filename, int key_len){
    FILE *fp = fopen(filename, "w");
    if(fp == NULL) return 0;

    int i;
    for(i = 0; i < n; i++){
        BIGNUM *bk = BN_bin2bn(leaf_blinds[i], key_len, NULL);
        char *hex = BN_bn2hex(bk);
        fprintf(fp, "%s\n", hex);
        OPENSSL_free(hex);
        BN_free(bk);
    }

    write_internal_nodes_postorder(root, fp, key_len);
    fclose(fp);
    return 1;
}

// Post-order recursive free. Frees all byte buffers and nodes
// The caller must NULL out its secret_bytes[]/blind_bytes[]
// entries before calling this to avoid double-free.
void free_tree(struct Node *node){
    if(node == NULL) return;
    free_tree(node->left);
    free_tree(node->right);
    if(node->secret_key != NULL) free(node->secret_key);
    if(node->blinded_key != NULL) free(node->blinded_key);
    free(node);
}
