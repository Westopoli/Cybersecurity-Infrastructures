/*
 * bob.c — Bob's role in the Arazi–Qi identity-based authenticated
 * key exchange on secp256k1.
 *
 * Online phase: loads CA-issued long-term material (x_b, U_b) and the
 * CA master public key D, generates the ephemeral public point
 *   E_b = p_b * P,
 * publishes it, then on seeing Alice's E_a derives the shared key
 *   K_ab = x_b * ( H(ID_A||U_a) * U_a + D ) + p_b * E_a.
 * Both parties arrive at the same K_ab without any certificate.
 *
 * Inputs  : argv[1..5] = x_b, U_b, p_b, U_a, D files (hex).
 * Outputs : bob_ephemeral_Eb.txt, bob_shared_key_Kab.txt.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

/* Fixed identity strings */
static const char *ID_A = "alice@example.com";
static const char *ID_B = "bob@example.com";

int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;

    /* === Cryptographic context === */
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;
    BN_CTX *ctx = NULL;

    /* === Long-term and ephemeral objects === */
    BIGNUM *x_b = NULL;   /* Bob private key */
    BIGNUM *p_b = NULL;   /* Bob ephemeral scalar */
    EC_POINT *U_b = NULL; /* Bob public identity point */
    EC_POINT *U_a = NULL; /* Alice public identity point */
    EC_POINT *D = NULL;   /* CA master public key */
    EC_POINT *E_b = NULL; /* Bob ephemeral public */
    EC_POINT *E_a = NULL; /* Alice ephemeral public */

    EC_POINT *temp1 = NULL;
    EC_POINT *temp2 = NULL;
    EC_POINT *K_ab = NULL;

    BIGNUM *h_A = NULL;
    BIGNUM *tmp = NULL;

    unsigned char *U_bytes = NULL;
    size_t U_len = 0;
    unsigned char *buf = NULL;
    size_t buf_len = 0;

    // Validate args: x_b, U_b, p_b, U_a, D (five hex-encoded files)
    if (argc != 6)
    {
        fprintf(stderr,
                "Usage: %s <x_b_file> <U_b_file> <p_b_file> <U_a_file> <D_file>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    // Initialize EC group on secp256k1 and obtain order q
    if(!init_group(&group, &q)){
		fprintf(stderr, "Group initialization failed.\n");
		goto cleanup;
	}
    // Obtain the curve generator P
    P = EC_GROUP_get0_generator(group);
	if(P == NULL){
		fprintf(stderr, "Could not obtain generator P.\n");
		goto cleanup;
	}
    // Allocate the BN context for modular arithmetic
    ctx = BN_CTX_new();
	if(ctx == NULL){
		fprintf(stderr, "BN_CTX allocation failed.\n");
		goto cleanup;
	}
    // Load Bob private witness x_b, then allocate and read EC points
    // U_b (Bob public), U_a (Alice public), D (CA master public)
    if(!read_bn_hex(argv[1], &x_b)){
		fprintf(stderr, "Could not read x_b from file.\n");
		goto cleanup;
	}

    U_a = EC_POINT_new(group);
	if(U_a == NULL){
		fprintf(stderr, "U_a allocation failed.\n");
		goto cleanup;
	}

	U_b = EC_POINT_new(group);
	if(U_b == NULL){
		fprintf(stderr, "U_b allocation failed.\n");
		goto cleanup;
	}

	D = EC_POINT_new(group);
	if(D == NULL){
		fprintf(stderr, "D allocation failed.\n");
		goto cleanup;
	}

    if(!read_point_hex(argv[2], group, &U_b)){
		fprintf(stderr, "Could not read U_b from file.\n");
		goto cleanup;
	}

	if(!read_point_hex(argv[4], group, &U_a)){
		fprintf(stderr, "Could not read U_a from file.\n");
		goto cleanup;
	}

	if(!read_point_hex(argv[5], group, &D)){
		fprintf(stderr, "Could not read D from file.\n");
		goto cleanup;
	}
    // Load Bob ephemeral scalar p_b
    if(!read_bn_hex(argv[3], &p_b)){
		fprintf(stderr, "Could not read p_b from file.\n");
		goto cleanup;
	}
    // Compute and publish Bob ephemeral public point E_b = p_b * P
    E_b = EC_POINT_new(group);
	if(E_b == NULL){
		fprintf(stderr, "E_b allocation failed.\n");
		goto cleanup;
	}

	// E_b = p_b * P
	if(!EC_POINT_mul(group, E_b, NULL, P, p_b, ctx)){
		fprintf(stderr, "Could not compute ephemeral public key.\n");
		goto cleanup;
	}

	// Publish E_b to disk for Alice
	if(!write_point_hex("bob_ephemeral_Eb.txt", group, E_b)){
		fprintf(stderr, "Could not write E_b to file.\n");
		goto cleanup;
	}
    // Try to load Alice's ephemeral public E_a; if absent, exit cleanly
    // so Alice can run next and complete the second leg of the exchange
    if(!read_point_hex("alice_ephemeral_Ea.txt", group, &E_a)){
		fprintf(stderr, "E_a file not found or could not be read.\n");
		ret = EXIT_SUCCESS;
		goto cleanup;
	}
    // Compute identity binding for Alice: h_A = H(ID_A || U_a) mod q

    // Serialize U_a to uncompressed octets
	if(!point_to_bytes(group, U_a, &U_bytes, &U_len)){
		fprintf(stderr, "U_a serialization failed.\n");
		goto cleanup;
	}

	// Build hash input buffer ID_A || U_a_bytes
    buf = malloc(strlen(ID_A) + U_len);
	memcpy(buf, ID_A, strlen(ID_A));
	buf_len = strlen(ID_A);
	memcpy(buf + strlen(ID_A), U_bytes, U_len);
	buf_len += U_len;

	// h_A = SHA-256(ID_A || U_a) reduced mod q
	if(!sha256_to_scalar(buf, buf_len, q, &h_A)){
		fprintf(stderr, "Failed to compute h_A.\n");
		goto cleanup;
	}
    // Compute shared key
    //   K_ab = x_b * ( h_A * U_a + D ) + p_b * E_a
    // The left summand is the identity-authenticated term;
    // the right summand is the ephemeral Diffie–Hellman term.
	temp1 = EC_POINT_new(group);
	if(temp1 == NULL){
		fprintf(stderr, "temp1 allocation failed.\n");
		goto cleanup;
	}
	temp2 = EC_POINT_new(group);
	if(temp2 == NULL){
		fprintf(stderr, "temp2 allocation failed.\n");
		goto cleanup;
	}
	K_ab = EC_POINT_new(group);
	if(K_ab == NULL){
		fprintf(stderr, "K_ab allocation failed.\n");
		goto cleanup;
	}

    // temp1 = h_A * U_a
	if(!EC_POINT_mul(group, temp1, NULL, U_a, h_A, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}

	// temp1 = temp1 + D
	if(!EC_POINT_add(group, temp1, temp1, D, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}

	// temp2 = x_b * temp1
	if(!EC_POINT_mul(group, temp2, NULL, temp1, x_b, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}
	
	// temp1 = p_b * E_a
	if(!EC_POINT_mul(group, temp1, NULL, E_a, p_b, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}

	// K_ab  = temp2 + temp1
	if(!EC_POINT_add(group, K_ab, temp1, temp2, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}
    // Persist the derived shared key
    if(!write_point_hex("bob_shared_key_Kab.txt", group, K_ab)){
		fprintf(stderr, "Failed to write K_ab to file.\n");
		goto cleanup;
	}
    printf("[Bob] Shared key K_ab computed and written.\n");
    ret = EXIT_SUCCESS;

    // Free all OpenSSL objects and buffers
cleanup:
	BN_free(x_b);
	BN_free(p_b);
	
	EC_POINT_free(U_a);
	EC_POINT_free(U_b);
	EC_POINT_free(D);
	EC_POINT_free(E_a);
	EC_POINT_free(E_b);

	EC_POINT_free(temp1);
	EC_POINT_free(temp2);
	EC_POINT_free(K_ab);

	BN_free(h_A);
	BN_free(tmp);

	free(U_bytes); 
	free(buf);

    EC_GROUP_free(group);
	BN_free(q);
	BN_CTX_free(ctx);
    return ret;
}
