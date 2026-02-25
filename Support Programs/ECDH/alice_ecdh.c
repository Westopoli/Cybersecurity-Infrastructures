#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>    // Elliptic Curve structures and functions
#include <openssl/evp.h>   // High-level OpenSSL cryptographic API
#include <openssl/err.h>   // OpenSSL error reporting
#include <openssl/sha.h>   // SHA-256 hash function
#include "utils.c"         // Utility functions: Read_File, Write_File, Convert_to_Hex

int main(int argc, char *argv[])
{
    /* ============================================================
     * STEP 0: Check command-line arguments
     * ============================================================
     * Alice requires a seed file to deterministically derive
     * her private key.
     */
    if (argc < 2)
    {
        printf("Usage: %s <seed_file>\n", argv[0]);
        return 0;
    }

    /* ============================================================
     * STEP 1: Create a BIGNUM context
     * ============================================================
     * BN_CTX is used internally by OpenSSL to manage temporary
     * big number variables efficiently.
     */
    BN_CTX *bn_ctx = BN_CTX_new();

    /* ============================================================
     * STEP 2: Read seed file
     * ============================================================
     * The seed is used as input entropy to derive Alice’s
     * elliptic-curve private key.
     */
    int seed_len;
    unsigned char *seed_str = Read_File(argv[1], &seed_len);

    if (seed_len < 32)
    {
        printf("Seed length must be at least 32 bytes.\n");
        return 0;
    }

    /* ============================================================
     * STEP 3: Hash the seed to derive a private key
     * ============================================================
     * A cryptographic hash (SHA-256) is used to map the seed
     * into a uniformly distributed 256-bit value.
     */
    unsigned char hash[SHA256_DIGEST_LENGTH];

    /* 
     * Use SHA256() to hash the first 32 bytes of the seed
     * and store the result in `hash`.
     *
     * SHA256(input, input_len, output)
     */

     SHA256(seed_str, seed_len, hash);

    /* ============================================================
     * STEP 4: Convert private key to hex and store it
     * ============================================================
     * Hex encoding is used only for debugging and demonstration.
     * In real systems, private keys should never be written to disk.
     */
    char sk_hex[2 * SHA256_DIGEST_LENGTH + 1];

    /* TODO:
     * Convert the 32-byte private key hash into hexadecimal
     * using Convert_to_Hex().
     */

    sk_hex[2 * SHA256_DIGEST_LENGTH] = '\0';
    Write_File("alice/key_sk_hex.txt", sk_hex);

    /* ============================================================
     * STEP 5: Convert private key into BIGNUM
     * ============================================================
     * OpenSSL EC functions operate on BIGNUM values.
     */
    BIGNUM *sk = BN_new();

    /* 
     * Convert the hex-encoded private key into a BIGNUM
     * using BN_hex2bn().
     */
    BN_hex2bn(sk, sk_hex);

    /* ============================================================
     * STEP 6: Initialize elliptic curve parameters
     * ============================================================
     * secp256k1 is a widely used 256-bit elliptic curve.
     */
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    /* ============================================================
     * STEP 7: Compute Alice’s public key
     * ============================================================
     * Public key = sk * G
     * where:
     *   sk = Alice’s private key
     *   G  = curve base point
     */
    EC_POINT *pk_point = EC_POINT_new(group);

    /* 
     * Use EC_POINT_mul() to compute:
     *   pk_point = sk * G
     *
     * Hint:
     *   EC_POINT_mul(group, result, n, Q, m, ctx)
     */

     EC_POINT_mul(group, pk_point, sk, NULL, NULL, bn_ctx);

    /* ============================================================
     * STEP 8: Convert public key to uncompressed hex
     * ============================================================
     * Format:
     *   04 || X || Y
     */
    char *pk_hex = NULL;

    /* 
     * Convert pk_point to a hex string using
     * EC_POINT_point2hex().
     */
    EC_POINT_point2hx(group, pk_point, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);


    /* ============================================================
     * STEP 9: Save Alice’s public key
     * ============================================================ */
    Write_File("alice/key_pk_hex.txt", pk_hex);

    /* ============================================================
     * STEP 10: Read Bob’s public key
     * ============================================================ */
    int bob_pk_len;
    char *bob_pk_hex = Read_File("bob/key_pk_hex.txt", &bob_pk_len);

    if (!bob_pk_hex)
    {
        printf("Alice: Bob’s public key not found. Run Bob first.\n");
        return 0;
    }

    /* ============================================================
     * STEP 11: Convert Bob’s public key to EC_POINT
     * ============================================================ */
    EC_POINT *bob_pk_point = EC_POINT_new(group);

    /* 
     * Convert Bob’s public key hex string into an EC_POINT
     * using EC_POINT_hex2point().
     */
    EC_POINT_hex2point(group, bob_pk_hex, bob_pk_point, bn_ctx);

    /* ============================================================
     * STEP 12: Compute ECDH shared secret
     * ============================================================
     * Shared secret = sk * Bob_PK
     */
    EC_POINT *secret_point = EC_POINT_new(group);

    /* 
     * Use EC_POINT_mul() to compute:
     *   secret_point = sk * bob_pk_point
     */

     EC_POINT_mul(group, secret_point, NULL, bob_pk_point, sk, bn_ctx);

    /* ============================================================
     * STEP 13: Convert shared secret to hex and save
     * ============================================================ */
    char *secret_hex = NULL;

    /* 
     * Convert secret_point to hex using EC_POINT_point2hex()
     * and write it to alice/secret_hex.txt.
     */
    secret_hex = EC_POINT_point2hex(group, secret_point, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);

    /* ============================================================
     * STEP 14: Cleanup
     * ============================================================
     * Free all allocated OpenSSL and heap resources.
     */
    OPENSSL_free(pk_hex);
    OPENSSL_free(secret_hex);
    EC_POINT_free(pk_point);
    EC_POINT_free(bob_pk_point);
    EC_POINT_free(secret_point);
    EC_KEY_free(eckey);
    BN_free(sk);
    BN_CTX_free(bn_ctx);
    free(seed_str);
    free(bob_pk_hex);

    printf("Alice: Shared secret computed successfully.\n");
    return 0;
}
