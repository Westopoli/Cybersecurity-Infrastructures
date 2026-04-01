/*
 * alice.c — Node Alice for Arazi–Qi Key Exchange (ECDLP)
 *
 * ============================
 * ASSIGNMENT TEMPLATE VERSION
 * ============================
 *
 * STUDENT TASK:
 *   Implement Alice’s online (ephemeral) phase and shared key computation
 *   for the Arazi–Qi identity-based authenticated Diffie–Hellman protocol.
 *
 *   You MUST NOT change:
 *     - File names
 *     - Variable names
 *     - Identity strings
 *     - Function signatures
 *
 *   You MUST replace all TODO sections with working code
 *   using the specified helper functions and OpenSSL APIs.
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

	/* =====================================================
	 * 1. Command-line argument validation
	 * =====================================================
	 *
	 * REQUIRED invocation:
	 *
	 *   ./alice <x_a_file> <U_a_file> <p_a_file> <U_b_file> <D_file>
	 *
	 * ARGUMENTS:
	 *   argv[1] : alice_private_xa.txt
	 *   argv[2] : alice_public_Ua.txt
	 *   argv[3] : alice_ephemeral_pa.txt
	 *   argv[4] : bob_public_Ub.txt
	 *   argv[5] : ca_master_public_D.txt
	 *
	 * ACTION:
	 *   - If argc != 6, print usage and EXIT_FAILURE.
	 */

	if (argc != 6)
	{
		fprintf(stderr,
				"Usage: %s <x_a_file> <U_a_file> <p_a_file> <U_b_file> <D_file>\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	/* =====================================================
	 * 2. Initialize elliptic curve group
	 * =====================================================
	 *
	 * TASK:
	 *   - Initialize EC_GROUP using a named curve
	 *   - Retrieve group order q
	 *
	 * FUNCTION:
	 *   init_group(&group, &q)
	 *
	 * EXIT on failure.
	 */

	// TODO: Call init_group(&group, &q)
	if(!init_group(&group, &q)){
		fprintf(stderr, "Group initialization failed.\n");
		goto cleanup;
	}
	/* =====================================================
	 * 3. Obtain generator P
	 * =====================================================
	 *
	 * FUNCTION:
	 *   EC_GROUP_get0_generator(group)
	 *
	 * EXIT if P == NULL.
	 */

	// TODO: Set P = EC_GROUP_get0_generator(group)
	P = EC_GROUP_get0_generator(group);
	if(P == NULL){
		fprintf(stderr, "Could not obtain generator P.\n");
		goto cleanup;
	}
	/* =====================================================
	 * 4. Allocate BN_CTX
	 * =====================================================
	 *
	 * FUNCTION:
	 *   BN_CTX_new()
	 *
	 * EXIT if allocation fails.
	 */

	// TODO: Allocate ctx
	ctx = BN_CTX_new();
	if(ctx == NULL){
		fprintf(stderr, "BN_CTX allocation failed.\n");
		goto cleanup;
	}
	/* =====================================================
	 * 5. Load Alice and system public parameters
	 * =====================================================
	 *
	 * FILE INPUTS:
	 *   argv[1] : x_a (scalar)
	 *   argv[2] : U_a (EC point)
	 *   argv[4] : U_b (EC point)
	 *   argv[5] : D   (EC point)
	 *
	 * FUNCTIONS:
	 *   read_bn_hex
	 *   EC_POINT_new
	 *   read_point_hex
	 *
	 * EXIT if any file does not exist or parsing fails.
	 */

	// TODO: Read x_a from argv[1]
	// TODO: Allocate U_a, U_b, D using EC_POINT_new
	// TODO: Read U_a from argv[2]
	// TODO: Read U_b from argv[4]
	// TODO: Read D from argv[5]
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
	/* =====================================================
	 * 6. Load Alice ephemeral scalar p_a
	 * =====================================================
	 *
	 * FILE INPUT:
	 *   argv[3] : alice_ephemeral_pa.txt
	 *
	 * FUNCTION:
	 *   read_bn_hex
	 *
	 * EXIT if missing or invalid.
	 */

	// TODO: Read p_a from argv[3]
	if(!read_bn_hex(argv[3], &p_a)){
		fprintf(stderr, "Could not read p_a from file.\n");
		goto cleanup;
	}
	/* =====================================================
	 * 7. Compute Alice ephemeral public E_a
	 * =====================================================
	 *
	 * FORMULA:
	 *   E_a = p_a * P
	 *
	 * FUNCTION:
	 *   EC_POINT_mul
	 *
	 * OUTPUT FILE:
	 *   alice_ephemeral_Ea.txt
	 */

	// TODO: Allocate E_a
	// TODO: Compute E_a = p_a * P
	// TODO: Write alice_ephemeral_Ea.txt
	
	// Allocate E_a
	E_a = EC_POINT_new(group);
	if(E_a == NULL){
		fprintf(stderr, "E_a allocation failed.\n");
		goto cleanup;
	}

	// Compute E_a
	if(!EC_POINT_mul(group, E_a, NULL, P, p_a, ctx)){
		fprintf(stderr, "Could not compute ephemeral public key.\n");
		goto cleanup;
	}

	// Write E_a to file
	if(!write_point_hex("alice_ephemeral_Ea.txt", group, E_a)){
		fprintf(stderr, "Could not write E_a to file.\n");
		goto cleanup;
	}
	/* =====================================================
	 * 8. Read Bob ephemeral public E_b (if available)
	 * =====================================================
	 *
	 * FILE INPUT:
	 *   bob_ephemeral_Eb.txt
	 *
	 * FUNCTION:
	 *   read_point_hex
	 *
	 * BEHAVIOR:
	 *   - If file does NOT exist:
	 *       * Print informational message
	 *       * Exit successfully after writing E_a
	 */

	// TODO: Attempt to read bob_ephemeral_Eb.txt into E_b
	if(!read_point_hex("bob_ephemeral.Eb.txt", group, &E_b)){
		fprintf(stderr, "E_b file not found or could not be read.\n");
		ret = EXIT_SUCCESS;
		goto cleanup;
	}
	/* =====================================================
	 * 9. Compute h_B = H(ID_B || U_b)
	 * =====================================================
	 *
	 * STEPS:
	 *   1. Serialize U_b to bytes
	 *      Function: point_to_bytes
	 *   2. Concatenate ID_B || U_b_bytes
	 *   3. Hash and reduce mod q
	 *      Function: sha256_to_scalar
	 */

	// TODO: Serialize U_b
	// TODO: Build hash buffer
	// TODO: Compute h_B

	// Serialize U_b to U_bytes
	if(!point_to_bytes(group, U_b, &U_bytes, &U_len)){
		fprintf(stderr, "U_b serialization failed.\n");
		goto cleanup;
	}

	// Load buffer with ID_B || U_bytes
	memcpy(buf, ID_B, sizeof(ID_B));
	buf_len = sizeof(ID_B);
	memcpy(buf + sizeof(ID_B), U_bytes, U_len);
	buf_len += U_len;

	// Compute h_B
	if(!sha256_to_scalar(buf, buf_len, q, &h_B)){
		fprintf(stderr, "Failed to compute h_B.\n");
		goto cleanup;
	}

	/* =====================================================
	 * 10. Compute shared key K_ab
	 * =====================================================
	 *
	 * FORMULA:
	 *
	 *   K_ab =
	 *     x_a * ( H(ID_B||U_b) * U_b + D )
	 *     + p_a * E_b
	 *
	 * FUNCTIONS:
	 *   EC_POINT_mul
	 *   EC_POINT_add
	 *
	 * STEPS:
	 *   temp1 = H * U_b
	 *   temp1 = temp1 + D
	 *   temp2 = x_a * temp1
	 *   temp1 = p_a * E_b
	 *   K_ab  = temp2 + temp1
	 */

	// TODO: Allocate temp1, temp2, K_ab
	// TODO: Compute H * U_b
	// TODO: Add D
	// TODO: Multiply by x_a
	// TODO: Compute p_a * E_b
	// TODO: Add results into K_ab
	
	// Allocate temp1, temp2, K_ab 
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
	if(!EC_POINT_add(group, K_ab, temp1, temp1, ctx)){
		fprintf(stderr, "Error in K_ab calculation.\n");
		goto cleanup;
	}
	/* =====================================================
	 * 11. Write shared key to disk
	 * =====================================================
	 *
	 * OUTPUT FILE:
	 *   alice_shared_key_Kab.txt
	 *
	 * FUNCTION:
	 *   write_point_hex
	 */

	// TODO: Write alice_shared_key_Kab.txt
	if(!write_point_hex("alice_shared_key_Kab.txt", group, K_ab)){
		fprintf(stderr, "Failed to write K_ab to file.\n");
		goto cleanup;
	}
	printf("[Alice] Shared key K_ab computed and written.\n");
	ret = EXIT_SUCCESS;

	/* =====================================================
	 * 12. Cleanup
	 * =====================================================
	 *
	 * TASK:
	 *   Free ALL allocated objects using:
	 *     BN_free
	 *     EC_POINT_free
	 *     EC_GROUP_free
	 *     BN_CTX_free
	 */

cleanup:
	EC_GROUP_free(group);
	BN_free(q);
	EC_POINT_free(P);
	BN_CTX_free(ctx);

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
	return ret;
}
