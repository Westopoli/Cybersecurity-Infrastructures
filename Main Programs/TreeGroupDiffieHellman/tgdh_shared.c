/*
Tree-based Group Diffie-Hellman (TGDH) - Shared Helpers

Common utilities used by setup, join, leave, merge, and refresh: DH parameter
loading, hex/byte/BIGNUM conversions, leaf blinded key computation, tree
construction, bottom-up internal key derivation, and output writers.

Ownership model: the key tree owns every leaf and internal byte buffer. After
build_tree() returns, callers must NULL out their secret_bytes[] and
blind_bytes[] entries so free_tree() can safely release them without
double-freeing.

Crypto primitives: OpenSSL BIGNUM modular exponentiation, SHA-256.
DH parameters: RFC 2409 Group 2 (1024-bit MODP), g = 2.
*/
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

// Load DH generator g from a decimal-integer text file into a BIGNUM
BIGNUM* get_g(const char *filename){
    int g_int = Read_Int_From_File(filename);
    if(g_int == -1){
        return NULL;
    }

    BIGNUM* g = BN_new();
    if(g == NULL){
        return NULL;
    }

    // Wrap the integer value as a BIGNUM
    if(BN_set_word(g, g_int) == 0){
        BN_free(g);
        return NULL;
    }
    return g;
}

// Load DH modulus p from a hex-string text file into a BIGNUM
BIGNUM* get_p(const char *filename){
    int p_len = 0;
    char* p_string = Read_File(filename, &p_len);
    if(p_string == NULL){
        return NULL;
    }

    BIGNUM* p = NULL;

    // Parse the hex string into a BIGNUM
    if(BN_hex2bn(&p, p_string) == 0){
        free(p_string);
        return NULL;
    }
    free(p_string);
    return p;
}

// Parse a single hex string into a freshly allocated BIGNUM (NULL input ptr triggers allocation)
BIGNUM* hex_to_bn(const char *hex_string){
    BIGNUM *bn = NULL;
    if(BN_hex2bn(&bn, hex_string) == 0){
        return NULL;
    }
    return bn;
}

// Convert an array of raw SHA-256 digest buffers into a parallel array of BIGNUMs
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

// Read every hex secret line from filename into a newly allocated BIGNUM array
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

// One-shot SHA-256 over input -> 32-byte hash
int Compute_SHA256(const unsigned char *input, int inputlen, unsigned char *hash){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    return 1;
}

// Compute leaf blinded keys: blinds[i] = g^secrets[i] mod p
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

// Serialize a BIGNUM into a zero-padded big-endian byte buffer of length key_len.
// Caller takes ownership of the returned buffer (must free()).
unsigned char* bn_to_bytes(BIGNUM *bn, int key_len){
    unsigned char *buf = calloc(key_len, 1);
    if(buf == NULL) return NULL;
    int actual_len = BN_num_bytes(bn);
    // Right-align the magnitude so leading bytes stay zero (canonical big-endian fixed width)
    BN_bn2bin(bn, buf + (key_len - actual_len));
    return buf;
}

// Recursively build a left-heavy balanced binary tree over leaves
// secret_bytes[start .. start+n-1] / blind_bytes[start .. start+n-1].
// Internal nodes start with secret_key = blinded_key = NULL (filled by compute_internal_keys).
struct Node* build_tree(unsigned char **secret_bytes, unsigned char **blind_bytes, int start, int n){
    struct Node *node = malloc(sizeof(struct Node));
    if(node == NULL) return NULL;

    node->parent = NULL;
    node->left = NULL;
    node->right = NULL;

    if(n == 1){
        // Leaf node takes ownership of the caller's leaf byte buffers
        node->secret_key = secret_bytes[start];
        node->blinded_key = blind_bytes[start];
        return node;
    }

    // Split the leaf range with the larger half on the left (left-heavy layout)
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

// Post-order traversal: derive each internal node's keys from its children.
//   secret_key  = BK_left ^ K_right  mod p   (stored as key_len bytes)
//   blinded_key = g ^ secret_key     mod p   (stored as key_len bytes)
void compute_internal_keys(struct Node *node, BIGNUM *g, BIGNUM *p, int key_len, BN_CTX *ctx){
    if(node->left == NULL) return;  // leaf already populated by caller

    compute_internal_keys(node->left, g, p, key_len, ctx);
    compute_internal_keys(node->right, g, p, key_len, ctx);

    // Lift the child keys needed by the TGDH recurrence into BIGNUM form
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

// Write the root secret (the shared group key) to filename as an uppercase hex string.
// Uses BN_bn2hex for canonical output (no artificial leading zeros).
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

// Post-order traversal that writes only the internal nodes' blinded keys (one hex line each)
static void write_internal_nodes_postorder(struct Node *node, FILE *fp, int key_len){
    if(node->left == NULL) return;  // skip leaves; emitted separately by the caller
    write_internal_nodes_postorder(node->left, fp, key_len);
    write_internal_nodes_postorder(node->right, fp, key_len);

    BIGNUM *bk = BN_bin2bn(node->blinded_key, key_len, NULL);
    char *hex = BN_bn2hex(bk);
    fprintf(fp, "%s\n", hex);
    OPENSSL_free(hex);
    BN_free(bk);
}

// Write the full blinded-key listing to filename:
//   first the leaves left-to-right (from leaf_blinds[0..n-1]),
//   then the internal nodes in post-order.
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

// Post-order recursive teardown: frees every node and every owned key buffer.
// Callers must first NULL out their secret_bytes[] / blind_bytes[] entries
// (whose pointers were transferred to the leaves) to avoid a double-free.
void free_tree(struct Node *node){
    if(node == NULL) return;
    free_tree(node->left);
    free_tree(node->right);
    if(node->secret_key != NULL) free(node->secret_key);
    if(node->blinded_key != NULL) free(node->blinded_key);
    free(node);
}
