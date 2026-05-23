/*
 * signer2.c — Level-2 Signer (ID_2) for the 2-level Schnorr-HIBS scheme.
 *
 * Performs two cryptographic phases in sequence:
 *   1. HIBS.Extract at hierarchy level k = 2 — derives the leaf-level
 *      signing key sk_ID2 from the level-1 secret key and a fresh
 *      delegation randomness b2.
 *   2. HIBS.Sign — produces a Schnorr-style signature (h, s) on a message
 *      under the effective hierarchical secret key sk_ID2.
 *
 * Cryptographic relations:
 *   Delegation:
 *     Q_ID2  = b2 * P
 *     c_ID2  = H1(ID_2 || Q_ID1 || Q_ID2)   mod q
 *     sk_ID2 = sk_ID1 * c_ID2 + b2          mod q
 *
 *   Signing:
 *     R = r * P                              (commitment point)
 *     h = H2(message || R)                   mod q
 *     s = r + h * sk_ID2                     mod q
 *
 * Input:
 *   argv[1] — sk_ID1.txt:       hex scalar (level-1 secret, from signer1)
 *   argv[2] — signer2_b2.txt:   hex delegation randomness b2
 *   argv[3] — signer2_r.txt:    hex per-signature randomness r
 *   argv[4] — Q_ID1.txt:        hex level-1 public delegation point
 *   argv[5] — ID2.txt:          identity string for level 2
 *   argv[6] — message.txt:      message to be signed
 *
 * Output:
 *   Q_ID2.txt — hex EC point (level-2 public delegation point)
 *   sig_s.txt — hex scalar s (signature response)
 *   sig_h.txt — hex scalar h (signature challenge)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

static char ID_2[1024];
static char MESSAGE[4096];

int main(int argc, char **argv)
{
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *sk_ID1 = NULL;
    EC_POINT *Q_ID1 = NULL;

    BIGNUM *b2 = NULL;
    EC_POINT *Q_ID2 = NULL;
    BIGNUM *c_ID2 = NULL;
    BIGNUM *sk_ID2 = NULL;

    BIGNUM *r = NULL;
    EC_POINT *R = NULL;
    BIGNUM *h = NULL;
    BIGNUM *s = NULL;

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *qid2_bytes = NULL;
    unsigned char *buf = NULL;
    unsigned char *R_bytes = NULL;
    unsigned char *hbuf = NULL;

    BIGNUM *tmp = NULL;
    BIGNUM *tmp2 = NULL;

    size_t id_len = 0;
    size_t m_len = 0;

    const char *sk_id1_path = NULL;
    const char *b2_path = NULL;
    const char *r_path = NULL;
    const char *q_id1_path = NULL;
    const char *id2_path = NULL;
    const char *msg_path = NULL;

    if (argc != 7)
    {
        fprintf(stderr,
            "Usage: %s <sk_ID1.txt> <signer2_b2.txt> <signer2_r.txt> "
            "<Q_ID1.txt> <ID2.txt> <message.txt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    sk_id1_path = argv[1];
    b2_path     = argv[2];
    r_path      = argv[3];
    q_id1_path  = argv[4];
    id2_path    = argv[5];
    msg_path    = argv[6];

    // Initialize EC group (secp256k1), extract order q, and obtain generator P
    if(init_group(&group, &q) == 0) {
        fprintf(stderr, "initializing elliptic curve group failed\n");
        return EXIT_FAILURE;
    }
    P = EC_GROUP_get0_generator(group);
    if(P == NULL) {
        fprintf(stderr, "initializing domain parameters failed\n");
        return EXIT_FAILURE;
    }

    // Load the level-1 secret scalar sk_ID1 and the level-1 public point Q_ID1
    if(read_bn_hex(sk_id1_path, &sk_ID1) == 0) {
        fprintf(stderr, "Reading sk_ID1 failed\n");
        return EXIT_FAILURE;
    }
    if(read_point_hex(q_id1_path, group, &Q_ID1) == 0) {
        fprintf(stderr, "Reading Q_ID1 failed\n");
        return EXIT_FAILURE;
    }

    // Read the level-2 identity ID_2 and the message to sign; trim trailing newlines
    FILE *f = fopen(id2_path, "r");
    if(f == NULL) {
        fprintf(stderr, "Opening ID2 file failed\n");
        return EXIT_FAILURE;
    }
    fgets(ID_2, sizeof(ID_2), f);
    fclose(f);
    id_len = strlen(ID_2);
    if(id_len > 0) {
        if(ID_2[id_len-1] == '\n')
            ID_2[--id_len] = '\0';
        else if(ID_2[id_len-1] == '\r')
            ID_2[--id_len] = '\0';
    }

    f = fopen(msg_path, "r");
    if(f == NULL) {
        fprintf(stderr, "Opening message file failed\n");
        return EXIT_FAILURE;
    }
    fgets(MESSAGE, sizeof(MESSAGE), f);
    fclose(f);
    m_len = strlen(MESSAGE);
    if(m_len > 0) {
        if(MESSAGE[m_len-1] == '\n')
            MESSAGE[--m_len] = '\0';
        else if(MESSAGE[m_len-1] == '\r')
            MESSAGE[--m_len] = '\0';
    }

    // Allocate BIGNUM context and output scalars (sk_ID2 for delegation, s for the signature)
    ctx = BN_CTX_new();
    if(ctx == NULL) {
        fprintf(stderr, "BN context allocation failed\n");
        return EXIT_FAILURE;
    }
    sk_ID2 = BN_new();
    if(sk_ID2 == NULL) {
        fprintf(stderr, "sk_ID2 allocation failed\n");
        return EXIT_FAILURE;
    }
    s = BN_new();
    if(s == NULL) {
        fprintf(stderr, "s allocation failed\n");
        return EXIT_FAILURE;
    }

    /****** DELEGATION PHASE ******/
    // Load delegation randomness b2 and compute the level-2 public point Q_ID2 = b2 * P
    if(read_bn_hex(b2_path, &b2) == 0) {
        fprintf(stderr, "Reading b2 failed\n");
        return EXIT_FAILURE;
    }
    Q_ID2 = EC_POINT_new(group);
    if(Q_ID2 == NULL) {
        fprintf(stderr, "Q_ID2 allocation failed\n");
        return EXIT_FAILURE;
    }
    if(EC_POINT_mul(group, Q_ID2, NULL, P, b2, ctx) == 0) {
        fprintf(stderr, "Computing Q_ID2 failed\n");
        return EXIT_FAILURE;
    }

    // Derive identity-binding scalar c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2) mod q.
    // Both EC points are serialized in uncompressed form before hashing-to-scalar.
    size_t qid1_len;
    if(point_to_bytes(group, Q_ID1, &qid1_bytes, &qid1_len) == 0) {
        fprintf(stderr, "Serializing Q_ID1 failed\n");
        return EXIT_FAILURE;
    }
    size_t qid2_len;
    if(point_to_bytes(group, Q_ID2, &qid2_bytes, &qid2_len) == 0) {
        fprintf(stderr, "Serializing Q_ID2 failed\n");
        return EXIT_FAILURE;
    }
    buf = malloc(id_len + qid1_len + qid2_len);
    if(buf == NULL) {
        fprintf(stderr, "Buffer allocation failed\n");
        return EXIT_FAILURE;
    }
    memcpy(buf, ID_2, id_len);
    memcpy(buf + id_len, qid1_bytes, qid1_len);
    memcpy(buf + id_len + qid1_len, qid2_bytes, qid2_len);
    if(H1_to_scalar(buf, id_len + qid1_len + qid2_len, q, &c_ID2) == 0) {
        fprintf(stderr, "H1 hash failed\n");
        return EXIT_FAILURE;
    }
    free(buf); buf = NULL;

    // Compute leaf-level secret key: sk_ID2 = sk_ID1 * c_ID2 + b2 mod q
    tmp = BN_new();
    if(tmp == NULL) {
        fprintf(stderr, "tmp allocation failed\n");
        return EXIT_FAILURE;
    }
    if(BN_mod_mul(tmp, sk_ID1, c_ID2, q, ctx) == 0) {
        fprintf(stderr, "BN_mod_mul failed\n");
        return EXIT_FAILURE;
    }
    if(BN_mod_add(sk_ID2, tmp, b2, q, ctx) == 0) {
        fprintf(stderr, "BN_mod_add failed\n");
        return EXIT_FAILURE;
    }

    /****** SIGNING PHASE ******/
    // Load per-signature randomness r and compute Schnorr commitment R = r * P
    if(read_bn_hex(r_path, &r) == 0) {
        fprintf(stderr, "Reading r failed\n");
        return EXIT_FAILURE;
    }
    R = EC_POINT_new(group);
    if(R == NULL) {
        fprintf(stderr, "R allocation failed\n");
        return EXIT_FAILURE;
    }
    if(EC_POINT_mul(group, R, NULL, P, r, ctx) == 0) {
        fprintf(stderr, "Computing R failed\n");
        return EXIT_FAILURE;
    }

    // Compute Schnorr challenge h = H2(message || R) mod q via the H2 hash-to-scalar
    size_t R_len;
    if(point_to_bytes(group, R, &R_bytes, &R_len) == 0) {
        fprintf(stderr, "Serializing R failed\n");
        return EXIT_FAILURE;
    }
    hbuf = malloc(m_len + R_len);
    if(hbuf == NULL) {
        fprintf(stderr, "hbuf allocation failed\n");
        return EXIT_FAILURE;
    }
    memcpy(hbuf, MESSAGE, m_len);
    memcpy(hbuf + m_len, R_bytes, R_len);
    if(H2_to_scalar(hbuf, m_len + R_len, q, &h) == 0) {
        fprintf(stderr, "H2 hash failed\n");
        return EXIT_FAILURE;
    }
    free(hbuf); hbuf = NULL;

    // Compute Schnorr response s = r + h * sk_ID2 mod q
    tmp2 = BN_new();
    if(tmp2 == NULL) {
        fprintf(stderr, "tmp2 allocation failed\n");
        return EXIT_FAILURE;
    }
    if(BN_mod_mul(tmp2, h, sk_ID2, q, ctx) == 0) {
        fprintf(stderr, "BN_mod_mul failed\n");
        return EXIT_FAILURE;
    }
    if(BN_mod_add(s, r, tmp2, q, ctx) == 0) {
        fprintf(stderr, "BN_mod_add failed\n");
        return EXIT_FAILURE;
    }

    // Publish the level-2 delegation point and the signature pair (h, s)
    if(write_point_hex("Q_ID2.txt", group, Q_ID2) == 0) {
        fprintf(stderr, "Writing Q_ID2 failed\n");
        return EXIT_FAILURE;
    }
    if(write_bn_hex("sig_s.txt", s) == 0) {
        fprintf(stderr, "Writing sig_s failed\n");
        return EXIT_FAILURE;
    }
    if(write_bn_hex("sig_h.txt", h) == 0) {
        fprintf(stderr, "Writing sig_h failed\n");
        return EXIT_FAILURE;
    }

    printf("[signer2] Delegation and signing complete.\n");

    // Release all BIGNUM, EC_POINT, buffer, and context resources
    if(tmp) BN_free(tmp);
    if(tmp2) BN_free(tmp2);
    if(buf) free(buf);
    if(hbuf) free(hbuf);
    if(qid1_bytes) free(qid1_bytes);
    if(qid2_bytes) free(qid2_bytes);
    if(R_bytes) free(R_bytes);
    if(h) BN_free(h);
    if(s) BN_free(s);
    if(c_ID2) BN_free(c_ID2);
    if(sk_ID2) BN_free(sk_ID2);
    if(b2) BN_free(b2);
    if(r) BN_free(r);
    if(R) EC_POINT_free(R);
    if(Q_ID2) EC_POINT_free(Q_ID2);
    if(Q_ID1) EC_POINT_free(Q_ID1);
    if(sk_ID1) BN_free(sk_ID1);
    if(ctx) BN_CTX_free(ctx);
    EC_GROUP_free(group);
    BN_free(q);

    return EXIT_SUCCESS;
}
