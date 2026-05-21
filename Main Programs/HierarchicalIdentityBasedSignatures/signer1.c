/*
 * signer1.c — Level-1 Signer (ID_1) for the 2-level Schnorr-HIBS scheme.
 *
 * Implements HIBS.Extract at hierarchy level k = 1. The level-1 signer takes
 * the PKG's master secret x along with its own identity string ID_1 and a
 * fresh delegation randomness b1, and produces (1) the level-1 secret key
 * sk_ID1 that will be passed down to the next-level signer and (2) the
 * public delegation point Q_ID1 used by both signer2 and the verifier to
 * reconstruct the effective public key.
 *
 * Cryptographic relations:
 *   Q_ID1  = b1 * P
 *   c_ID1  = H1(ID_1 || Q_ID1)            (hash-to-scalar mod q)
 *   sk_ID1 = x * c_ID1 + b1   mod q       (Schnorr-style delegation)
 *
 * Input:
 *   argv[1] — ID1.txt:         identity string for level 1
 *   argv[2] — signer1_b1.txt:  hex scalar b1 in Z_q
 *   argv[3] — msk.txt:         hex master secret x
 *
 * Output:
 *   sk_ID1.txt  — hex scalar (private, passed only to signer2)
 *   Q_ID1.txt   — hex uncompressed EC point (public)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

static char ID_1[1024];

int main(int argc, char **argv) {
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *x = NULL;        /* sk_ID0 (master secret scalar) */
    BIGNUM *b1 = NULL;       /* random delegation scalar */
    EC_POINT *Q_ID1 = NULL;  /* public delegation point */
    BIGNUM *c_ID1 = NULL;    /* hash-derived scalar */
    BIGNUM *sk_ID1 = NULL;   /* derived private key */

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *buf = NULL;
    BIGNUM *tmp = NULL;

    size_t id_len = 0;
    const char *id_path = NULL;
    const char *b1_path = NULL;
    const char *msk_path = NULL;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ID1.txt> <signer1_b1.txt> <msk.txt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    id_path  = argv[1];
    b1_path  = argv[2];
    msk_path = argv[3];

    // Initialize EC group (secp256k1), extract order q, and obtain the generator P
    if(init_group(&group, &q) == 0) {
		fprintf(stderr, "initializing elliptic curve group failed\n");
        return EXIT_FAILURE;
	}
    P = EC_GROUP_get0_generator(group);
    if(P == NULL) {
        fprintf(stderr, "initializing domain parameters failed\n");
        return EXIT_FAILURE;
    }

    // Load the master secret scalar x (the PKG's sk_ID0) from disk
    if(read_bn_hex(msk_path, &x) == 0) {
        fprintf(stderr, "Reading master secret failed\n");
        return EXIT_FAILURE;
    }

    // Read the level-1 identity string ID_1 and strip trailing newline/CR
    FILE *f = fopen(id_path, "r");
    if(f == NULL) {
        fprintf(stderr, "Opening identity file failed\n");
        return EXIT_FAILURE;
    }
    fgets(ID_1, sizeof(ID_1), f);
    fclose(f);
    id_len = strlen(ID_1);
    if(id_len > 0) {
        if(ID_1[id_len-1] == '\n')
            ID_1[--id_len] = '\0';
        else if(ID_1[id_len-1] == '\r')
            ID_1[--id_len] = '\0';
    }

    // Allocate BIGNUM context and output scalar sk_ID1
    ctx = BN_CTX_new();
    if(ctx == NULL) {
        fprintf(stderr, "BN context allocation failed\n");
        return EXIT_FAILURE;
    }
    sk_ID1 = BN_new();
    if(sk_ID1 == NULL) {
        fprintf(stderr, "sk_ID1 allocation failed\n");
        return EXIT_FAILURE;
    }

    // Load the per-delegation randomness b1 in Z_q
    if(read_bn_hex(b1_path, &b1) == 0) {
        fprintf(stderr, "Reading delegation randomness b1 failed\n");
        return EXIT_FAILURE;
    }

    // Compute the public delegation point Q_ID1 = b1 * P
    Q_ID1 = EC_POINT_new(group);
    if(Q_ID1 == NULL) {
        fprintf(stderr, "Q_ID1 allocation failed\n");
        return EXIT_FAILURE;
    }
    if(EC_POINT_mul(group, Q_ID1, NULL, P, b1, ctx) == 0) {
        fprintf(stderr, "Computing Q_ID1 failed\n");
        return EXIT_FAILURE;
    }

    // Derive the identity-binding scalar c_ID1 = H1(ID_1 || Q_ID1) mod q.
    // Serialize Q_ID1 to uncompressed octets, concatenate with ID_1, and
    // hash-to-scalar via the H1 domain-separated SHA-256 wrapper.
    size_t qid1_len;
    if(point_to_bytes(group, Q_ID1, &qid1_bytes, &qid1_len) == 0) {
        fprintf(stderr, "Serializing Q_ID1 failed\n");
        return EXIT_FAILURE;
    }
    buf = malloc(id_len + qid1_len);
    if(buf == NULL) {
        fprintf(stderr, "Buffer allocation failed\n");
        return EXIT_FAILURE;
    }
    memcpy(buf, ID_1, id_len);
    memcpy(buf + id_len, qid1_bytes, qid1_len);
    if(H1_to_scalar(buf, id_len + qid1_len, q, &c_ID1) == 0) {
        fprintf(stderr, "H1 hash failed\n");
        return EXIT_FAILURE;
    }
    free(buf); buf = NULL;

    // Compute the delegated secret key: sk_ID1 = x * c_ID1 + b1 mod q
    tmp = BN_new();
    if(tmp == NULL) {
        fprintf(stderr, "tmp allocation failed\n");
        return EXIT_FAILURE;
    }
    if(BN_mod_mul(tmp, x, c_ID1, q, ctx) == 0) {
        fprintf(stderr, "BN_mod_mul failed\n");
        return EXIT_FAILURE;
    }
    if(BN_mod_add(sk_ID1, tmp, b1, q, ctx) == 0) {
        fprintf(stderr, "BN_mod_add failed\n");
        return EXIT_FAILURE;
    }

    // Publish the level-1 secret key (for signer2) and the public delegation point
    if(write_bn_hex("sk_ID1.txt", sk_ID1) == 0) {
        fprintf(stderr, "Writing sk_ID1 failed\n");
        return EXIT_FAILURE;
    }
    if(write_point_hex("Q_ID1.txt", group, Q_ID1) == 0) {
        fprintf(stderr, "Writing Q_ID1 failed\n");
        return EXIT_FAILURE;
    }

    printf("[signer1] Delegation complete.\n");

    // Release all BIGNUM, EC_POINT, buffer, and context resources
    if(tmp) BN_free(tmp);
    if(buf) free(buf);
    if(qid1_bytes) free(qid1_bytes);
    if(c_ID1) BN_free(c_ID1);
    if(sk_ID1) BN_free(sk_ID1);
    if(b1) BN_free(b1);
    if(Q_ID1) EC_POINT_free(Q_ID1);
    if(x) BN_free(x);
    if(ctx) BN_CTX_free(ctx);
    EC_GROUP_free(group);
    BN_free(q);

    return EXIT_SUCCESS;
}
