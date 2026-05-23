/*
 * alice.c — Alice's role in the Arazi–Qi identity-based authenticated
 * key exchange on secp256k1.
 *
 * Online phase: loads CA-issued long-term material (x_a, U_a) and the
 * CA master public key D, generates the ephemeral public point
 *   E_a = p_a * P,
 * publishes it, then on seeing Bob's E_b derives the shared key
 *   K_ab = x_a * ( H(ID_B||U_b) * U_b + D ) + p_a * E_b.
 * The identity-binding term authenticates Bob without certificates.
 *
 * Inputs  : argv[1..5] = x_a, U_a, p_a, U_b, D files (hex).
 * Outputs : alice_ephemeral_Ea.txt, alice_shared_key_Kab.txt.
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
	BIGNUM *x_a = NULL;	  /* Alice private key */
	BIGNUM *p_a = NULL;	  /* Alice ephemeral scalar */
	EC_POINT *U_a = NULL; /* Alice public identity point */
	EC_POINT *U_b = NULL; /* Bob public identity point */
	EC_POINT *D = NULL;	  /* CA master public key */
	EC_POINT *E_a = NULL; /* Alice ephemeral public */
	EC_POINT *E_b = NULL; /* Bob ephemeral public */

	EC_POINT *temp1 = NULL;
	EC_POINT *temp2 = NULL;
	EC_POINT *K_ab = NULL;

	BIGNUM *h_B = NULL;
	BIGNUM *tmp = NULL;

	unsigned char *U_bytes = NULL;
	size_t U_len = 0;
	unsigned char *buf = NULL;
	size_t buf_len = 0;

	// Validate args: x_a, U_a, p_a, U_b, D (five hex-encoded files)
	if (argc != 6)
	{
		fprintf(stderr,
				"Usage: %s <x_a_file> <U_a_file> <p_a_file> <U_b_file> <D_file>\n",
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
	// Load Alice private witness x_a, then allocate and read EC points
	// U_a (Alice public), U_b (Bob public), D (CA master public)
	if(!read_bn_hex(argv[1], &x_a)){
		fprintf(stderr, "Could not read x_a from file.\n");
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

	if(!read_point_hex(argv[2], group, &U_a)){
		fprintf(stderr, "Could not read U_a from file.\n");
		goto cleanup;
	}

	if(!read_point_hex(argv[4], group, &U_b)){
		fprintf(stderr, "Could not read U_b from file.\n");
		goto cleanup;
	}

	if(!read_point_hex(argv[5], group, &D)){
		fprintf(stderr, "Could not read D from file.\n");
		goto cleanup;
	}
	// Load Alice ephemeral scalar p_a
	if(!read_bn_hex(argv[3], &p_a)){
		fprintf(stderr, "Could not read p_a from file.\n");
		goto cleanup;
	}
	// Compute and publish Alice ephemeral public point E_a = p_a * P
	E_a = EC_POINT_new(group);
	if(E_a == NULL){
		fprintf(stderr, "E_a allocation failed.\n");
		goto cleanup;
	}

	// E_a = p_a * P
	if(!EC_POINT_mul(group, E_a, NULL, P, p_a, ctx)){
		fprintf(stderr, "Could not compute ephemeral public key.\n");
		goto cleanup;
	}

	// Publish E_a to disk for Bob
	if(!write_point_hex("alice_ephemeral_Ea.txt", group, E_a)){
		fprintf(stderr, "Could not write E_a to file.\n");
		goto cleanup;
	}
	// Try to load Bob's ephemeral public E_b; if absent, exit cleanly
	// so Bob can run next and complete the second leg of the exchange
	if(!read_point_hex("bob_ephemeral_Eb.txt", group, &E_b)){
		fprintf(stderr, "E_b file not found or could not be read.\n");
		ret = EXIT_SUCCESS;
		goto cleanup;
	}
	// Compute identity binding for Bob: h_B = H(ID_B || U_b) mod q

	// Serialize U_b to uncompressed octets
	if(!point_to_bytes(group, U_b, &U_bytes, &U_len)){
		fprintf(stderr, "U_b serialization failed.\n");
		goto cleanup;
	}

	// Build hash input buffer ID_B || U_b_bytes
	buf = malloc(strlen(ID_B) + U_len);
	memcpy(buf, ID_B, strlen(ID_B));
	buf_len = strlen(ID_B);
	memcpy(buf + strlen(ID_B), U_bytes, U_len);
	buf_len += U_len;

	// h_B = SHA-256(ID_B || U_b) reduced mod q
	if(!sha256_to_scalar(buf, buf_len, q, &h_B)){
		fprintf(stderr, "Failed to compute h_B.\n");
		goto cleanup;
	}

	// Compute shared key
	//   K_ab = x_a * ( h_B * U_b + D ) + p_a * E_b
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

	// temp1 = h_B * U_b
	if(!EC_POINT_mul(group, temp1, NULL, U_b, h_B, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}

	// temp1 = temp1 + D
	if(!EC_POINT_add(group, temp1, temp1, D, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}

	// temp2 = x_a * temp1
	if(!EC_POINT_mul(group, temp2, NULL, temp1, x_a, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}
	
	// temp1 = p_a * E_b
	if(!EC_POINT_mul(group, temp1, NULL, E_b, p_a, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}

	// K_ab  = temp2 + temp1
	if(!EC_POINT_add(group, K_ab, temp1, temp2, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}
	// Persist the derived shared key
	if(!write_point_hex("alice_shared_key_Kab.txt", group, K_ab)){
		fprintf(stderr, "Failed to write K_ab to file.\n");
		goto cleanup;
	}
	printf("[Alice] Shared key K_ab computed and written.\n");
	ret = EXIT_SUCCESS;

	// Free all OpenSSL objects and buffers
cleanup:
	BN_free(x_a);
	BN_free(p_a);
	
	EC_POINT_free(U_a);
	EC_POINT_free(U_b);
	EC_POINT_free(D);
	EC_POINT_free(E_a);
	EC_POINT_free(E_b);

	EC_POINT_free(temp1);
	EC_POINT_free(temp2);
	EC_POINT_free(K_ab);

	BN_free(h_B);
	BN_free(tmp);

	free(U_bytes); 
	free(buf);

	EC_GROUP_free(group);
	BN_free(q);
	BN_CTX_free(ctx);

	return ret;
}
