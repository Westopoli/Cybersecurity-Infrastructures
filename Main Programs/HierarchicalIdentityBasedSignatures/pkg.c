/*
 * pkg.c — Private Key Generator (Level 0) for a 2-level Schnorr-HIBS scheme.
 *
 * Implements HIBS.Setup over the secp256k1 elliptic curve. The PKG is the
 * trusted authority at the root of the identity hierarchy: it loads the
 * master secret scalar x from disk, derives the master public key
 * mpk = x * P on the curve, and publishes mpk so downstream signers
 * (signer1, signer2) and the verifier can perform key delegation and
 * signature verification.
 *
 * Cryptographic role:
 *   - Master secret key: x in Z_q (kept private in pkg_x.txt)
 *   - Master public key: mpk = x * P (written to mpk.txt)
 *
 * Input:
 *   argv[1] — pkg_x.txt: hex-encoded scalar x with 1 <= x < q
 *
 * Output:
 *   mpk.txt — hex-encoded uncompressed EC point representing mpk
 *
 * Pseudocode
 *   Initialize EC group and obtain generator P
 *   Load master secret x from pkg_x.txt
 *   Compute mpk = x * P via EC scalar multiplication
 *   Serialize mpk in uncompressed hex form and write to mpk.txt
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#include "RequiredFunctions.h"

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	/* === Global cryptographic parameters === */
	EC_GROUP *group = NULL;      /* Elliptic curve group */
	BIGNUM *q = NULL;            /* Group order */
	const EC_POINT *P = NULL;    /* Generator point */

	/* === PKG keys === */
	BIGNUM *msk = NULL;          /* Master secret key x */
	EC_POINT *mpk = NULL;        /* Master public key x * P */

	BN_CTX *ctx = NULL;          /* BN context */

	// Initialize the named EC group (secp256k1) and extract its order q
	if(init_group(&group, &q) == 0) {
		fprintf(stderr, "initializing elliptic curve group failed\n");
		goto cleanup;
	}


	// Retrieve the curve's standard generator P (used for all scalar multiplications)
	P = EC_GROUP_get0_generator(group);
	if(P == NULL) {
		fprintf(stderr, "Point generator failed\n");
		goto cleanup;
	}

	// Validate command-line invocation: requires path to the master secret file
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <pkg_x.txt>\n", argv[0]);
		goto cleanup;
	}

	// Allocate a BIGNUM context for scratch storage used by EC scalar multiplication
	ctx = BN_CTX_new();
	if(ctx == NULL) {
		fprintf(stderr, "BN context failed to allocate\n");
		goto cleanup;
	}

	// Load hex-encoded master secret scalar x from the input file into a BIGNUM
	if(read_bn_hex(argv[1], &msk) == 0) {
		fprintf(stderr, "Loading master secret key failed\n");
		goto cleanup;
	}

	// Compute master public key mpk = x * P via EC scalar multiplication
	mpk = EC_POINT_new(group);
	if(mpk == NULL) {
		fprintf(stderr, "Master public key allocation failed\n");
		goto cleanup;
	}
	if(EC_POINT_mul(group, mpk, NULL, P, msk, ctx) == 0) {
		fprintf(stderr, "Eliiptic curve point multiplication failed\n");
		goto cleanup;
	}

	// Serialize mpk in uncompressed hex form and publish it via mpk.txt
	if(write_point_hex("mpk.txt", group, mpk) == 0) {
		fprintf(stderr, "Writing master PK to disk failed\n");
		goto cleanup;
	}
	printf("[PKG] Setup complete. Wrote mpk.txt.\n");
	ret = EXIT_SUCCESS;

	// Free all EC, BIGNUM, and context resources
cleanup:
	EC_POINT_free(mpk);
	BN_free(msk);
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
	BN_free(q);

	return ret;
}
