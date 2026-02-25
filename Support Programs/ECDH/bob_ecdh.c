#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>    // Elliptic Curve structures and operations
#include <openssl/evp.h>   // High-level OpenSSL cryptographic API
#include <openssl/err.h>   // OpenSSL error reporting
#include <openssl/sha.h>   // SHA-256 hash function
#include "utils.c"         // Utility functions: Read_File, Write_File, Convert_to_Hex

int main(int argc, char *argv[])
{
    /* ============================================================
     * STEP 0: Check command-line arguments
     * ============================================================
     * Bob requires a seed file to deterministically derive
     * his private key.
     */
    if (argc < 2)
    {
        printf("Usage: %s <seed_file>\n", argv[0]);
        return 0;
    }

    /* ============================================================
     * STEP 1: Create a BIGNUM context
     * ============================================================
     * BN_CTX manages temporary BIGNUM variables used internally
     * by OpenSSL for elliptic curve arithmetic.
     */
    BN_CTX *bn_ctx = BN_CTX_new();

    /* ============================================================
     * STEP 2: Read seed file
     * ============================================================
     * The seed provides entropy used to derive Bob’s
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
     * SHA-256 maps the seed deterministically into a
     * uniformly distributed 256-bit scalar.
     */
    unsigned char hash[SHA256_DIGEST_LENGTH];

    /* TODO:
     * Use SHA256() to hash the first 32 bytes of the seed
     * and store the result in `hash`.
     */

    /* ============================================================
     * STEP 4: Convert private key to hex and store it
     * ============================================================
     * Hex encoding is for demonstration only.
     * Private keys should never be stored unprotected in practice.
     */
    char sk_hex[2 * SHA256_DIGEST_LENGTH + 1];

    /* TODO:
     * Convert the 32-byte private key hash into hexadecimal
     * using Convert_to_Hex().
     */

    sk_hex[2 * SHA256_DIGEST_LENGTH] = '\0';
    Write_File("bob/key_sk_hex.txt", sk_hex);

    /* ============================================================
     * STEP 5: Convert private key to BIGNUM
     * ============================================================
     * OpenSSL EC APIs operate on BIGNUM scalars.
     */
    BIGNUM *sk = BN_new();

    /* TODO:
     * Convert the hex-encoded private key into a BIGNUM
     * using BN_hex2bn().
     */

    /* ============================================================
     * STEP 6: Initialize elliptic curve parameters
     * ============================================================
     * secp256k1 is a 256-bit prime-order elliptic curve.
     */
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    /* ============================================================
     * STEP 7: Compute Bob’s public key
     * ============================================================
     * Public key = sk * G
     * where:
     *   sk = Bob’s private key
     *   G  = curve base point
     */
    EC_POINT *pk_point = EC_POINT_new(group);

    /* TODO:
     * Use EC_POINT_mul() to compute:
     *   pk_point = sk * G
     */

    /* ============================================================
     * STEP 8: Convert public key to uncompressed hex
     * ============================================================
     * Format:
     *   04 || X || Y
     */
    char *pk_hex = NULL;

    /* TODO:
     * Convert pk_point to a hex string using
     * EC_POINT_point2hex().
     */

    /* ============================================================
     * STEP 9: Save Bob’s public key
     * ============================================================ */
    Write_File("bob/key_pk_hex.txt", pk_hex);

    /* ============================================================
     * STEP 10: Read Alice’s public key
     * ============================================================ */
    int alice_pk_len;
    char *alice_pk_hex = Read_File("alice/key_pk_hex.txt", &alice_pk_len);

    if (!alice_pk_hex)
    {
        printf("Bob: Alice’s public key not found. Run Alice first.\n");
        return 0;
    }

    /* ============================================================
     * STEP 11: Convert Alice’s public key to EC_POINT
     * ============================================================ */
    EC_POINT *alice_pk_point = EC_POINT_new(group);

    /* TODO:
     * Convert Alice’s public key hex string into an EC_POINT
     * using EC_POINT_hex2point().
     */

    /* ============================================================
     * STEP 12: Compute ECDH shared secret
     * ============================================================
     * Shared secret = sk * Alice_PK
     */
    EC_POINT *secret_point = EC_POINT_new(group);

    /* TODO:
     * Use EC_POINT_mul() to compute:
     *   secret_point = sk * alice_pk_point
     */

    /* ============================================================
     * STEP 13: Convert shared secret to hex and store
     * ============================================================ */
    char *secret_hex = NULL;

    /* TODO:
     * Convert secret_point to hex using EC_POINT_point2hex()
     * and write it to bob/secret_hex.txt.
     */

    /* ============================================================
     * STEP 14: Cleanup
     * ============================================================
     * Free all allocated OpenSSL and heap resources.
     */
    OPENSSL_free(pk_hex);
    OPENSSL_free(secret_hex);
    EC_POINT_free(pk_point);
    EC_POINT_free(alice_pk_point);
    EC_POINT_free(secret_point);
    EC_KEY_free(eckey);
    BN_free(sk);
    BN_CTX_free(bn_ctx);
    free(seed_str);
    free(alice_pk_hex);

    printf("Bob: Shared secret computed successfully.\n");
    return 0;
}
