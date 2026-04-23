// Condensed RSA (CRSA) with Multiplicative Homomorphism
//
// RSA signatures have a special algebraic property: if you multiply two
// signatures together (mod n), the result is a valid signature on the
// PRODUCT of the two original hashes 
// This is "multiplicative homomorphism"
// Condensed RSA exploits it to compress j individual signatures into a
// single aggregate of the same size 
// The verifier (who has all the messages)
// recomputes the product of hashes and checks the one aggregate signature
//
// What this program does:
// 1 Reads RSA key parameters (e, d, n) from rsa_paramstxt
// 2 Reads a hex encoded message from messagetxt, decodes it to binary
// 3 Splits the binary message into 128 byte blocks
// 4 For each block: hash it with SHA 256, then RSA sign the hash
// 5 Multiplies all individual signatures together mod n (the aggregate)
// 6 Writes individual_rsatxt (one sig per line, uppercase hex)
//    and condensed_rsatxt (single aggregate sig, uppercase hex)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// OpenSSL headers give us arbitrary precision integers (BIGNUM) for
// 2048 bit math and the SHA 256 hash function Linked via lcrypto
#include <openssl/bn.h>
#include <openssl/sha.h>

#define BLOCK_SIZE   128
#define RSA_HEX_LEN 512


// Converts a single hex character to its numeric value (0 through 15)
// '0' through '9' map to 0 through 9 'a' through 'f' (and uppercase)
// map to 10 through 15, which is why we add 10 after subtracting 'a'
static unsigned char hex_char_to_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    fprintf(stderr, "Invalid hex character: '%c'\n", c);
    exit(1);
}

// hex_decode: convert a hex string to raw bytes
static unsigned char *hex_decode(const char *hex_str, size_t *out_len)
{
    size_t hex_len = strlen(hex_str);

    // Each byte is represented by 2 hex characters, so the length must be even
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Hex string has odd length (%zu)\n", hex_len);
        exit(1);
    }

    *out_len = hex_len / 2;
    unsigned char *buf = malloc(*out_len);
    if (!buf) {
        perror("malloc");
        exit(1);
    }

    for (size_t i = 0; i < *out_len; i++) {
        unsigned char high = hex_char_to_val(hex_str[2 * i]);
        unsigned char low  = hex_char_to_val(hex_str[2 * i + 1]);
        buf[i] = (high << 4) | low;
    }

    return buf;
}


// read_file_text: slurps an entire file into a null terminated string
// Used for both rsa_paramstxt and messagetxt
//
// Approach:
// 1 fseek to the end to learn the file size
// 2 malloc that many bytes plus 1 for the null terminator
// 3 fseek back to the start, fread everything
// 4 Strip trailing whitespace so hex parsing doesn't choke on
//    invisible characters at the end of the file
static char *read_file_text(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open file: %s\n", path);
        exit(1);
    }

    // Jump to end to measure the file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate buffer: file contents plus null terminator
    char *buf = malloc(file_size + 1);
    if (!buf) {
        perror("malloc");
        exit(1);
    }

    fread(buf, 1, file_size, fp);
    buf[file_size] = '\0';
    fclose(fp);

    // Strip trailing whitespac
    size_t len = strlen(buf);

    // Walk backwards from the end, skipping whitespace
    size_t end = len;
    while (end > 0) {
        char c = buf[end - 1];

        int is_whitespace = (c == '\n') || (c == '\r')
                         || (c == ' ')  || (c == '\t');

        if (!is_whitespace) {
            break;
        }

        end--;
    }

    // cut the string at the last real character
    buf[end] = '\0';

    return buf;
}


// main: orchestrates the entire program
//
// Flow:
// 1 Parse command line arguments (rsa_paramstxt, messagetxt)
// 2 Read RSA parameters (e, d, n) into BIGNUMs
// 3 Read and hex decode the message into raw bytes
// 4 Loop over 128 byte blocks: hash, sign, accumulate
// 5 Write output files
int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s rsa_params.txt message.txt\n", argv[0]);
        return 1;
    }

    // 1
    char *params_text = read_file_text(argv[1]);

    char *e_hex = params_text;

    char *first_newline = strchr(params_text, '\n');
    if (!first_newline) {
        fprintf(stderr, "rsa_params.txt: expected 3 lines, found only 1\n");
        return 1;
    }
    *first_newline = '\0';

    char *d_hex = first_newline + 1;

    char *second_newline = strchr(d_hex, '\n');
    if (!second_newline) {
        fprintf(stderr, "rsa_params.txt: expected 3 lines, found only 2\n");
        return 1;
    }
    *second_newline = '\0';

    char *n_hex = second_newline + 1;

    // 2
    BIGNUM *e_bn = NULL, *d_bn = NULL, *n_bn = NULL;
    BN_hex2bn(&e_bn, e_hex);
    BN_hex2bn(&d_bn, d_hex);
    BN_hex2bn(&n_bn, n_hex);

    // 3
    char *msg_hex = read_file_text(argv[2]);

    size_t msg_len;
    unsigned char *msg_bin = hex_decode(msg_hex, &msg_len);

    int num_blocks = msg_len / BLOCK_SIZE;

    printf("Message: %zu bytes → %d blocks of %d bytes\n",
           msg_len, num_blocks, BLOCK_SIZE);

    // 4
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *sig_i   = BN_new();
    BIGNUM *sig_agg = BN_new();
    BIGNUM *hash_bn = BN_new();

    BN_one(sig_agg);

    FILE *fp_individual = fopen("individual_rsa.txt", "w");
    FILE *fp_condensed  = fopen("condensed_rsa.txt", "w");
    if (!fp_individual || !fp_condensed) {
        fprintf(stderr, "Cannot open output files for writing\n");
        return 1;
    }

    for (int i = 0; i < num_blocks; i++) {

        // Hash ths block with SHA 256
        unsigned char *block_start = msg_bin + (i * BLOCK_SIZE);

        unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
        SHA256(block_start, BLOCK_SIZE, hash_bytes);

        // Convert hash bytes to a BIGNUN
        BN_bin2bn(hash_bytes, SHA256_DIGEST_LENGTH, hash_bn);

        // RSA sign the hash: sig_i = hash_bn ^ d mod n
        BN_mod_exp(sig_i, hash_bn, d_bn, n_bn, ctx);

        // Accumulate into the aggregate: sig_agg = sig_agg * sig_i mod n
        BN_mod_mul(sig_agg, sig_agg, sig_i, n_bn, ctx);

        // write this individual signature to the output file
        char *sig_hex = BN_bn2hex(sig_i);
        

        if (i > 0) {
            fprintf(fp_individual, "\n");
        }

        // This ended up causing an error in test 4, adding extra zeroes 
        // when the expected output doesn't want it
        
        // int sig_hex_len = strlen(sig_hex);
        // int padding_needed = RSA_HEX_LEN - sig_hex_len;
        // for (int p = 0; p < padding_needed; p++) {
        //     fprintf(fp_individual, "0");
        // }

        fprintf(fp_individual, "%s", sig_hex);

        OPENSSL_free(sig_hex);
    }

    // 5
    char *agg_hex = BN_bn2hex(sig_agg);
    int agg_hex_len = strlen(agg_hex);

    int padding_needed = RSA_HEX_LEN - agg_hex_len;
    for (int p = 0; p < padding_needed; p++) {
        fprintf(fp_condensed, "0");
    }
    fprintf(fp_condensed, "%s", agg_hex);

    OPENSSL_free(agg_hex);

    fclose(fp_individual);
    fclose(fp_condensed);

    BN_free(e_bn);
    BN_free(d_bn);
    BN_free(n_bn);
    BN_free(sig_i);
    BN_free(sig_agg);
    BN_free(hash_bn);
    BN_CTX_free(ctx);
    free(params_text);
    free(msg_hex);
    free(msg_bin);

    return 0;
}
