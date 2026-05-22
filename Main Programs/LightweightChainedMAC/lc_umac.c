/*
Lightweight Chained Universal MAC (LC-UMAC)

This program implements a one-time universal-hash-based MAC over the prime field Z_q,
following the Carter-Wegman construction. Each message block M(i) is authenticated under
a fresh pair of field elements (a(i), b(i)) as tag(i) = a(i) * M(i) + b(i) mod q. The
per-block tags are aggregated additively mod q into a single compact aggregate tag,
yielding O(1) tag size regardless of the number of blocks.

Technical Details: ChaCha20 in OpenSSL is used as a PRNG to expand a shared seed into
the (a, b) key pairs. BIGNUM arithmetic from OpenSSL provides modular multiply/add over q.

I/O Contract:
    Input  (argv):
        argv[1] q.txt        - hex-encoded prime modulus q
        argv[2] seed.txt     - hex-encoded shared PRNG seed (ChaCha20 key)
        argv[3] message.txt  - hex-encoded message, partitioned into n blocks of |q| bytes
    Output (files):
        a.txt      - per-block hex coefficients a(i), one per line
        b.txt      - per-block hex coefficients b(i), one per line
        tags.txt   - per-block hex tags tag(i) = a(i)*M(i) + b(i) mod q
        aggtag.txt - hex aggregate tag = sum_i tag(i) mod q
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

unsigned char* read_file(const char *filename, int *length);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
int write_lines_to_file_hex(const char* filename, unsigned char** lines, int n, int len);
unsigned char *hex_to_bytes(const char *hex, int* bytes_len);
int write_bn_file(unsigned char* filename, BIGNUM* bn, int byte_len);
BIGNUM* calc_lc_umac(unsigned char* tag_filename, unsigned char** m_seq, unsigned char** a_seq, unsigned char** b_seq, unsigned char* q, int block_byte_len, int num_blocks);


int main(int argc, char* argv[]){
    if(argc != 4){
        fprintf(stderr, "Usage: 'Command' q.txt seed.txt message.txt");
        return 1;
    }

    unsigned char* q_hex = NULL;
    unsigned char* q_bytes = NULL;
    unsigned char* shared_seed = NULL;
    unsigned char* shared_seed_bytes = NULL;
    unsigned char* message_hex = NULL;
    unsigned char* message_bytes = NULL;
    unsigned char* random_str = NULL;

    unsigned char** M = NULL;
    unsigned char** a = NULL;
    unsigned char** b = NULL; 
    
    int q_len = 0;
    int q_blen = 0; // |q| in bytes (field-element width)
    int seed_len = 0;
    int seed_len_bytes = 0;
    int message_hex_len = 0;
    int message_bytes_len = 0;

    int i = 0;
    int n = 0;  // Number of message blocks of width |q|

    BIGNUM* aggre_lc_umac = NULL;

    // Load prime modulus q from hex file and decode to raw bytes
    q_hex = read_file(argv[1], &q_len);
    if(q_hex == NULL){
        fprintf(stderr, "Error reading q from file.\n");
        goto cleanup;
    }
    q_bytes = hex_to_bytes(q_hex, &q_blen);

    // Load shared ChaCha20 PRNG seed from hex file and decode to raw bytes
    shared_seed = read_file(argv[2], &seed_len);
    if(shared_seed == NULL){
        fprintf(stderr, "Error reading shared seed from file.\n");
        goto cleanup;
    }
    shared_seed_bytes = hex_to_bytes(shared_seed, &seed_len_bytes);
    if(shared_seed_bytes == NULL){
        fprintf(stderr, "Failed to convert hex to bytes.\n");
        goto cleanup;
    }

    // Load hex message, decode to bytes, derive block count n = |msg| / |q|
    message_hex = read_file(argv[3], &message_hex_len);
    if(message_hex == NULL){
        fprintf(stderr, "Error reading q from file.\n");
        goto cleanup;
    }

    message_bytes = hex_to_bytes(message_hex, &message_bytes_len);
    if(message_bytes == NULL){
        fprintf(stderr, "Error converting message from hex to bytes.\n");
        goto cleanup;
    }
    n = message_bytes_len / q_blen;



    // Expand shared seed via ChaCha20 into 2*n*|q| pseudorandom bytes for the (a, b) key stream
    random_str = PRNG(shared_seed_bytes, seed_len_bytes, 2 * n * q_blen);
    if(random_str == NULL){
        fprintf(stderr, "Error generating random byte string.\n");
        goto cleanup;
    }

    for (int i = 0; i < 2 * n * q_blen; i++) {
    if (random_str[i] == 0xAA) {
        printf("UNINITIALIZED at %d\n", i);
    }
}
    // for (int i = 0; i < 2 * n * q_blen; i++) printf("%02X", random_str[i]);
    // printf("\n");
    // printf("messbytlen: %d\nqbytelen: %d", message_bytes_len, q_blen);

    


    // Slice the message byte stream into n equal-sized blocks M[0..n-1] of |q| bytes
    M = malloc(n * sizeof(unsigned char*));
    if(M == NULL){
        fprintf(stderr, "M allocation failed.\n");
        goto cleanup;
    }

    for(i = 0; i < n; i++){
        M[i] = malloc(q_blen);
        if(M[i] == NULL){
            fprintf(stderr, "M row allocation failed.\n");
            goto cleanup;
        }

        memcpy(M[i], message_bytes + i * q_blen, q_blen);
    }

    // Split the PRNG keystream into interleaved per-block field elements a[i] and b[i]
    a = malloc(n * sizeof(unsigned char*));
    if(a == NULL){
        fprintf(stderr, "a allocation failed.\n");
        goto cleanup;
    }
    b = malloc(n * sizeof(unsigned char*));
    if(b == NULL){
        fprintf(stderr, "b allocation failed.\n");
        goto cleanup;
    }

    for(i = 0; i < n; i++){
        a[i] = malloc(q_blen);
        if(a[i] == NULL){
            fprintf(stderr, "a row allocation failed.\n");
            goto cleanup;
        }
        memcpy(a[i], random_str + i * 2 * q_blen, q_blen);

        b[i] = malloc(q_blen);
        if(b[i] == NULL){
            fprintf(stderr, "b row allocation failed.\n");
            goto cleanup;
        }
        memcpy(b[i], random_str + q_blen + i * 2 * q_blen, q_blen);
    }

    // printf("q: %s\nSeed: %s\nMessage: %s\n", q, shared_seed, message);
    // printf("n: %d\n", n);
    // printf("message len: %d\nq len: %d\nq blen: %d\n", message_hex_len, q_len, q_blen);
    // for(i = 0; i < q_blen; i++){
    //     printf("a: %02X\n", a[i]);
    // }

    // printf("Random string: ");
    // for(i = 0; i < 2 * n * q_blen; i++){
    //     printf("%02X", random_str[i]);
    // }
    
    // Persist the per-block UMAC keys (a, b) as hex, one block per line
    i = write_lines_to_file_hex("a.txt", a, n, q_blen);
    if(i == 0){
        goto cleanup;
    }

    i = write_lines_to_file_hex("b.txt", b, n, q_blen);
    if(i == 0){
        goto cleanup;
    }
    
    // Compute per-block Carter-Wegman tags tag(i) = a(i)*M(i) + b(i) mod q and the aggregate sum
    aggre_lc_umac = calc_lc_umac("tags.txt", M, a, b, q_bytes, q_blen, n);
    
    // Write the compact O(1) aggregate tag = sum_i tag(i) mod q to disk
    write_bn_file("aggtag.txt", aggre_lc_umac, q_blen);

    cleanup:

    return 0;
}

unsigned char* read_file(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *buffer = (char*)malloc(file_size + 1);
    if (!buffer) { fclose(file); return NULL; }
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    while (read_size > 0 && (buffer[read_size-1] == '\n' || 
           buffer[read_size-1] == '\r' || buffer[read_size-1] == ' '))
        buffer[--read_size] = '\0';
    *length = (int)read_size;
    fclose(file);
    return buffer;
}

unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen){
    
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *pseudoRandomNumber = malloc(prnglen);

    unsigned char nonce[16] = {0};
    
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce) != 1) {
        fprintf(stderr, "ChaCha init failed\n");
    }
    // unsigned char zeros[prnglen];
    // memset(zeros, 0, prnglen);

    unsigned char *zeros = calloc(prnglen, 1);
    // for (int i = 0; i < prnglen; i++) {
    // if (pseudoRandomNumber[i] == 0x00)
    //     printf("ZERO BYTE at %d\n", i);
    // }
    int outlen = 0;
    // EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    // EVP_EncryptFinal(ctx, pseudoRandomNumber, &outlen);

    int ret = EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    if (ret != 1) {
        fprintf(stderr, "PRNG failed\n");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    free(zeros);
    return pseudoRandomNumber;
}

int write_lines_to_file_hex(const char* filename, unsigned char** lines, int n, int byte_len){
    FILE* fp = fopen(filename, "w");
    if(!fp){
        fprintf(stderr, "Error opening file %s for writing.\n", filename);
        return 0;
    }

    for(int i = 0; i < n; i++){
        for(int j = 0; j < byte_len; j++){
            fprintf(fp, "%02X", lines[i][j]);
        }
        fprintf(fp, "\n");
    }
    fclose(fp);
    return 1;    
}        

unsigned char *hex_to_bytes(const char *hex, int* bytes_len){
    // Reject odd-length hex (not a valid byte-aligned encoding)
    int hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return NULL;
    }

    *bytes_len = hex_len / 2;
    unsigned char *bytes = malloc(*bytes_len);
    if (!bytes) {
        return NULL;
    }

    // Decode each hex pair into a raw byte
    for (size_t i = 0; i < *bytes_len; i++) {
        int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) {
            free(bytes);
            return NULL;
        }
        bytes[i] = (unsigned char)byte;
    }

    return bytes;
}

// Serialize a BIGNUM as fixed-width hex (preserves leading zero bytes for field-element width)
int write_bn_file(unsigned char* filename, BIGNUM* bn, int byte_len){
    // BN_bn2hex() strips leading zeros; pad to |q| bytes first via BN_bn2binpad, then hex-encode
    unsigned char* byte_buf = malloc(byte_len);

    int i = BN_bn2binpad(bn, byte_buf, byte_len);
    if(i < 0){
        free(byte_buf);
        return 0;
    }

    // Overwrite any prior file, then append padded hex line
    remove(filename);
    FILE* fp = fopen(filename, "a");
    if(fp == NULL){
        free(byte_buf);
        return 0;
    }
    for(i = 0; i < byte_len; i++){
        fprintf(fp, "%02X", byte_buf[i]);
    }
    fprintf(fp, "\n");
    free(byte_buf);
    fclose(fp);

    return 1;
}

// Computes per-block Carter-Wegman tags over Z_q and returns their modular sum as the aggregate tag
BIGNUM* calc_lc_umac(unsigned char* tag_filename, unsigned char** m_seq, unsigned char** a_seq, unsigned char** b_seq, unsigned char* q, int block_byte_len, int num_blocks){
    BIGNUM* temp = NULL;
    BIGNUM* m_bn = NULL;
    BIGNUM* a_bn = NULL;
    BIGNUM* b_bn = NULL;
    BIGNUM* umac = NULL;

    BIGNUM* aggre_umac = BN_new();
    BN_zero(aggre_umac);

    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* q_bn = BN_bin2bn(q, block_byte_len, NULL);
    
    temp = BN_new();
    umac = BN_new();
    
    for(int i = 0; i < num_blocks; i++){
        a_bn = BN_bin2bn(a_seq[i], block_byte_len, NULL);
        if(a_bn == NULL){
            goto err_cleanup;
        }
        b_bn = BN_bin2bn(b_seq[i], block_byte_len, NULL);
        if(b_bn == NULL){
            goto err_cleanup;
        }
        m_bn = BN_bin2bn(m_seq[i], block_byte_len, NULL);
        if(m_bn == NULL){
            goto err_cleanup;
        }

        // Per-block Carter-Wegman tag: umac = (a * m + b) mod q
        BN_mod_mul(temp, a_bn, m_bn, q_bn, ctx);
        BN_mod_add(umac, temp, b_bn, q_bn, ctx);

        
        
        int j;
        j = write_bn_file(tag_filename, umac, block_byte_len);

        BN_mod_add(aggre_umac, umac, aggre_umac, q_bn, ctx);

        BN_free(a_bn);
        BN_free(b_bn);
        BN_free(m_bn);
        
    }
    BN_free(temp);
    BN_free(umac);
    BN_free(q_bn);
    BN_CTX_free(ctx);

    return aggre_umac;

    err_cleanup:
    BN_free(q_bn);
    BN_free(a_bn);
    BN_free(b_bn);
    BN_free(m_bn);
    BN_free(temp);
    BN_free(umac);
    BN_free(aggre_umac);
    BN_CTX_free(ctx);
    
    return NULL;

}