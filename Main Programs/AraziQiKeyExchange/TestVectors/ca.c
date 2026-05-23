/*
 * ca.c — Certification Authority for the Arazi–Qi identity-based
 * authenticated key exchange protocol on secp256k1.
 *
 * Offline phase: generates the CA master secret d and master public
 * key D = d*P, then issues per-user identity material for Alice and
 * Bob. For each user with identity ID and random scalar b, computes
 *   U   = b * P
 *   h   = H(ID || U) mod q
 *   x   = (h * b + d) mod q
 * U is the user's public identity point; x is the private witness
 * binding the identity to the CA master secret.
 *
 * Inputs  : hex scalar files d, b_a, b_b (argv[1..3]).
 * Outputs : ca_master_secret_d.txt, ca_master_public_D.txt,
 *           alice_private_xa.txt, alice_public_Ua.txt,
 *           bob_private_xb.txt,  bob_public_Ub.txt.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

/* Public identity strings */
static const char *ID_A = "alice@example.com";
static const char *ID_B = "bob@example.com";

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	/* === Cryptographic objects === */
	EC_GROUP *group = NULL;      /* Elliptic curve group */
	BIGNUM *q = NULL;            /* Group order */
	const EC_POINT *P = NULL;    /* Generator */
	BN_CTX *ctx = NULL;

	BIGNUM *d = NULL;            /* CA master secret */
	EC_POINT *D = NULL;          /* CA master public key */

	BIGNUM *b_a = NULL;
	BIGNUM *b_b = NULL;
	EC_POINT *U_a = NULL;
	EC_POINT *U_b = NULL;

	BIGNUM *h_a = NULL;
	BIGNUM *h_b = NULL;
	BIGNUM *x_a = NULL;
	BIGNUM *x_b = NULL;
	BIGNUM *tmp = NULL;

	unsigned char *U_bytes = NULL;
	size_t U_len = 0;
	unsigned char *buf = NULL;
	size_t buf_len = 0;

	// Validate args: ./ca <d_file> <b_a_file> <b_b_file> (all hex scalars)
	if (argc != 4)
	{
		fprintf(stderr, "Usage: %s <d_file> <b_a_file> <b_b_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	// Initialize EC group on secp256k1 and obtain order q
	if(!init_group(&group, &q)){
		fprintf(stderr, "EC_GROUP initialization failed.\n");
		goto cleanup;
	}
	// Obtain the curve generator P
	P = EC_GROUP_get0_generator(group);
	if(P == NULL){
		fprintf(stderr, "Could not obtain generator P.\n");
		goto cleanup;
	}
	// Allocate BN context and master key objects (d scalar, D point)
	ctx = BN_CTX_new();
	if(ctx == NULL){
		fprintf(stderr, "BN_CTX allocation failed.\n");
		goto cleanup;
	}

	d = BN_new();
	if(d == NULL){
		fprintf(stderr, "d allocation failed.\n");
		goto cleanup;
	}

	D = EC_POINT_new(group);
	if(D == NULL){
		fprintf(stderr, "D allocation failed.\n");
		goto cleanup;
	}
	
	// Load CA master secret d from hex file
	if(!read_bn_hex(argv[1], &d)){
		fprintf(stderr, "Could not read master secret from file.\n");
		goto cleanup;
	}
	// Compute CA master public key D = d * P
	if(!EC_POINT_mul(group, D, NULL, P, d, ctx)){
		fprintf(stderr, "Could not compute master public key.\n");
		goto cleanup;
	}
	// Persist CA master keys (d as scalar, D as EC point) in hex
	if(!write_bn_hex("ca_master_secret_d.txt", d)){
		fprintf(stderr, "Failed to write master secret to file.\n");
		goto cleanup;
	}

	if(!write_point_hex("ca_master_public_D.txt", group, D)){
		fprintf(stderr, "Failed to write master public to file.\n");
		goto cleanup;
	}
	// Allocate per-user scalars and points for Alice and Bob
	b_a = BN_new();
	if(b_a == NULL){
		fprintf(stderr, "b_a allocation failed.\n");
		goto cleanup;
	}

	b_b = BN_new();
	if(b_b == NULL){
		fprintf(stderr, "b_b allocation failed.\n");
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

	x_a = BN_new();
	if(x_a == NULL){
		fprintf(stderr, "x_a allocation failed.\n");
		goto cleanup;
	}

	x_b = BN_new();
	if(x_b == NULL){
		fprintf(stderr, "x_b allocation failed.\n");
		goto cleanup;
	}

	tmp = BN_new();
	if(tmp == NULL){
		fprintf(stderr, "temp allocation failed.\n");
		goto cleanup;
	}
	// Load per-user random scalars b_a and b_b from hex files
	if(!read_bn_hex(argv[2], &b_a)){
		fprintf(stderr, "Could not load b_a from file.\n");
		goto cleanup;
	}

	if(!read_bn_hex(argv[3], &b_b)){
		fprintf(stderr, "Could not load b_b from file.\n");
		goto cleanup;
	}
	// Alice offline key issuance: U_a = b_a*P, h_a = H(ID_A||U_a) mod q,
	// x_a = (h_a*b_a + d) mod q

	// Compute Alice public identity point U_a = b_a * P
	if(!EC_POINT_mul(group, U_a, NULL, P, b_a, ctx)){
		fprintf(stderr, "U_a computation failed.\n");
		goto cleanup;
	}
	
	// Serialize U_a to its uncompressed octet form
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

	// Compute identity-binding scalar h_a = H(ID_A || U_a) mod q
	if(!sha256_to_scalar(buf, buf_len, q, &h_a)){
		fprintf(stderr, "Failed to compute h_a.\n");
		goto cleanup;
	}

	// Compute Alice private witness x_a = (h_a * b_a + d) mod q
	if(!BN_mod_mul(x_a, h_a, b_a, q, ctx)){
		fprintf(stderr, "x_a computation failed.\n");
		goto cleanup;
	}
	if(!BN_mod_add(x_a, x_a, d, q, ctx)){
		fprintf(stderr, "x_a computation failed.\n");
		goto cleanup;
	}

	// Persist Alice key material (x_a scalar, U_a point) to disk
	if(!write_bn_hex("alice_private_xa.txt", x_a)){
		fprintf(stderr, "Failed to write to 'alice_private_xa.txt'.\n");
		goto cleanup;
	}
	if(!write_point_hex("alice_public_Ua.txt", group, U_a)){
		fprintf(stderr, "Failed to write to 'alice_public_Ua.txt'.\n");
		goto cleanup;
	}
	free(buf);

	// Bob offline key issuance: same construction with (ID_B, b_b)

	// Compute Bob public identity point U_b = b_b * P
	if(!EC_POINT_mul(group, U_b, NULL, P, b_b, ctx)){
		fprintf(stderr, "U_b computation failed.\n");
		goto cleanup;
	}
	
	// Serialize U_b to its uncompressed octet form
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

	// Compute identity-binding scalar h_b = H(ID_B || U_b) mod q
	if(!sha256_to_scalar(buf, buf_len, q, &h_b)){
		fprintf(stderr, "Failed to compute h_b.\n");
		goto cleanup;
	}

	// Compute Bob private witness x_b = (h_b * b_b + d) mod q
	if(!BN_mod_mul(x_b, h_b, b_b, q, ctx)){
		fprintf(stderr, "x_b computation failed.\n");
		goto cleanup;
	}
	if(!BN_mod_add(x_b, x_b, d, q, ctx)){
		fprintf(stderr, "x_b computation failed.\n");
		goto cleanup;
	}

	// Persist Bob key material (x_b scalar, U_b point) to disk
	if(!write_bn_hex("bob_private_xb.txt", x_b)){
		fprintf(stderr, "Failed to write to 'bob_private_xb.txt'.\n");
		goto cleanup;
	}
	if(!write_point_hex("bob_public_Ub.txt", group, U_b)){
		fprintf(stderr, "Failed to write to 'bob_public_Ub.txt'.\n");
		goto cleanup;
	}

	printf("[CA] Offline keys generated for Alice and Bob.\n");
	ret = EXIT_SUCCESS;

	// Free all OpenSSL objects and buffers
cleanup:
	BN_free(d);
	EC_POINT_free(D);

	BN_free(b_a);
	BN_free(b_b);
	EC_POINT_free(U_a);
	EC_POINT_free(U_b);

	BN_free(h_a);
	BN_free(h_b);
	BN_free(x_a);
	BN_free(x_b);
	BN_free(tmp);

	free(U_bytes);
	free(buf); 

	EC_GROUP_free(group);
	BN_free(q);
	BN_CTX_free(ctx);
	
	return ret;
}
