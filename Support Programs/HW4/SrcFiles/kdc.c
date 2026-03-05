#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

// #include <unistd.h> // For access() if needed

/*
 * ============================================================
 * Kerberos KDC / Authentication Server — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files or alter their formats.
 *  - The grading scripts depend strictly on these filenames.
 *
 * This program implements the Authentication Service (AS)
 * portion of a simplified, file-based Kerberos protocol.
 *
 * All long-term keys and temporary keys are assumed to have
 * been generated BEFORE this program runs.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (AS PHASE):
 *
 * 1) Verify the client’s signature on its temporary public key
 * 2) Derive a shared secret using ECDH (Elliptic Curve Diffie-Hellman)
 * 3) Derive Key_Client_AS from the shared secret
 * 4) Issue a Ticket Granting Ticket (TGT)
 * 5) Build and encrypt AS_REP.txt
 *
 * Cryptographic concepts involved:
 *  - ECDSA signature verification
 *  - ECDH key agreement
 *  - SHA-256 key derivation
 *  - AES-256 encryption (ECB for simplicity in this demo)
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Read and understand them before implementing this file.
 *
 * ============================================================
 */

 /*
 * KDC.C - Key Distribution Center (Authentication Server role)
 *
 * Invocation: ./kdc <Client_Signature.txt> <Client_temp_PK.txt>
 *                   <AS_temp_SK.txt> <AS_temp_PK.txt>
 *
 * ARGUMENT CHECK
 *   Verify exactly 4 command-line arguments are provided.
 *   If not, print usage message and exit with EXIT_FAILURE.
 *
 * VERIFY INPUT FILES EXIST
 *   Check that Client_Signature.txt, AS_temp_SK.txt, and AS_temp_PK.txt
 *   are all present on disk.
 *   If any are missing, print an error and exit.
 *
 * VERIFY CLIENT SIGNATURE (ECDSA)
 *   Load the long-term client verification key from Client_PK.txt.
 *   Verify the ECDSA signature in Client_Signature.txt
 *   over the contents of Client_temp_PK.txt.
 *   If verification fails, terminate — the client is not authenticated.
 *
 * COMPUTE ECDH SHARED SECRET
 *   Compute: shared_secret = ECDH(AS_temp_SK, Client_temp_PK)
 *   Write the hex-encoded shared secret to shared_secret.txt.
 *
 * DERIVE CLIENT-AS SESSION KEY (SHA-256)
 *   Hash the shared secret using SHA-256 to produce Key_Client_AS.
 *   Write the hex-encoded key to Key_Client_AS.txt.
 *
 * READ PRE-GENERATED SESSION KEYS
 *   Read the 256-bit client-TGS session key from Key_Client_TGS.txt (hex).
 *   Read the shared AS-TGS symmetric key from Key_AS_TGS.txt (hex).
 *   If either file is unreadable or invalid, terminate.
 *
 * BUILD THE TICKET GRANTING TICKET (AES-256-ECB)
 *   Construct TGT plaintext as:
 *     TGT_plain = "Client" || Key_Client_TGS_hex
 *   Encrypt TGT_plain using AES-256-ECB with Key_AS_TGS.
 *   Hex-encode the resulting ciphertext to produce TGT.
 *
 * BUILD AND WRITE THE AS REPLY (AES-256-ECB)
 *   Construct AS reply plaintext as:
 *     AS_REP_plain = Key_Client_TGS (32 raw bytes) || TGT (hex string)
 *   Encrypt AS_REP_plain using AES-256-ECB with Key_Client_AS.
 *   Write the hex-encoded ciphertext to AS_REP.txt.
 *   If any encryption or file-write step fails, exit with error.
 *
 * COMPLETION
 *   Exit with EXIT_SUCCESS.
 *   The AS phase is complete: the client has been authenticated and
 *   a TGT has been issued for use with the TGS.
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[])
{

	/* ------------------------------------------------------------
	 * Command-line arguments:
	 *
	 * argv[1] : Client_Signature.txt
	 * argv[2] : Client_temp_PK.txt
	 * argv[3] : AS_temp_SK.txt
	 * argv[4] : AS_temp_PK.txt
	 *
	 * These files MUST already exist.
	 * The KDC must NOT generate any keys here.
	 * ------------------------------------------------------------
	 */
	if (argc != 5)
	{
		fprintf(stderr,
				"Usage: %s <Client_Signature> <Client_temp_PK> <AS_temp_SK> <AS_temp_PK>\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_sig_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_sk_path = argv[3];
	const char *as_temp_pk_path = argv[4];

	/* Buffers for cryptographic material */
	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];

	/* ------------------------------------------------------------
	 * STEP 0: Verify required input files exist
	 *
	 * The AS must ensure:
	 *  - Client signature file exists
	 *  - AS temporary key pair exists
	 *
	 * Abort immediately on missing files.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of:
	 *        client_sig_path
	 *        as_temp_sk_path
	 *        as_temp_pk_path
	 *  - Print descriptive errors and exit on failure
	 */

	// Elegant solution
	// if (access(client_sig_path, F_OK) == -1) {
	// 	fprintf(stderr, "Error: Client signature file '%s' not found.\n", client_sig_path);
	// 	return EXIT_FAILURE;
	// }
	// if (access(as_temp_sk_path, F_OK) == -1) {
	// 	fprintf(stderr, "Error: AS temporary private key file '%s' not found.\n", as_temp_sk_path);
	// 	return EXIT_FAILURE;
	// }
	// if (access(as_temp_pk_path, F_OK) == -1) {
	// 	fprintf(stderr, "Error: AS temporary public key file '%s' not found.\n", as_temp_pk_path);
	// 	return EXIT_FAILURE;
	// }

	FILE *fp = fopen(client_sig_path, "r");

	if (fp == NULL) {
		fprintf(stderr, "Error: Client signature file '%s' not found.\n", client_sig_path);
		return EXIT_FAILURE;
	}
	fclose(fp);
	fp = fopen(as_temp_sk_path, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: AS temporary private key file '%s' not found.\n", as_temp_sk_path);
		return EXIT_FAILURE;
	}
	fclose(fp);
	fp = fopen(as_temp_pk_path, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: AS temporary public key file '%s' not found.\n", as_temp_pk_path);
		return EXIT_FAILURE;
	}
	fclose(fp);

	/* ------------------------------------------------------------
	 * STEP 1: Verify client identity
	 *
	 * The client authenticates by signing its temporary
	 * public key using its long-term private key.
	 *
	 * Verification inputs:
	 *  - Client_PK.txt        (long-term client public key)
	 *  - Client_temp_PK.txt  (signed data)
	 *  - Client_Signature.txt
	 *
	 * Abort if verification fails.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Verify ECDSA signature
	 *  - Use Client_PK.txt as the verification key
	 *  - Treat failure as an authentication failure
	 */

	ecdsa_verify_file_from_hex("Client_PK.txt", client_temp_pk_path, client_sig_path);

	/* ------------------------------------------------------------
	 * STEP 2: Derive shared secret (ECDH)
	 *
	 * Compute:
	 *
	 *   shared_secret = ECDH(AS_temp_SK, Client_temp_PK)
	 *
	 * The raw shared secret MUST be written to:
	 *      "shared_secret.txt"   (hex format)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Perform ECDH using the AS temporary private key
	 *  - Use the client's temporary public key
	 *  - Write the shared secret to shared_secret.txt (hex)
	 */

	/* ------------------------------------------------------------
	 * STEP 3: Derive Key_Client_AS
	 *
	 * Compute:
	 *
	 *   Key_Client_AS = SHA256(shared_secret)
	 *
	 * Write the derived key to:
	 *      "Key_Client_AS.txt"   (hex format, 32 bytes)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Hash the shared secret using SHA-256
	 *  - Write exactly 32 bytes to Key_Client_AS.txt
	 */

	/* ------------------------------------------------------------
	 * STEP 4: Load pre-generated session key (Client ↔ TGS)
	 *
	 * For this demo, the KDC does NOT generate a new
	 * Key_Client_TGS. Instead, it reads an existing one:
	 *
	 *      "Key_Client_TGS.txt"
	 *
	 * This file must contain exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_Client_TGS.txt (hex)
	 *  - Validate length
	 *  - Store raw bytes in key_client_tgs
	 */

	/* ------------------------------------------------------------
	 * STEP 5: Build the Ticket Granting Ticket (TGT)
	 *
	 * TGT plaintext format:
	 *
	 *      "Client" || Key_Client_TGS_hex
	 *
	 * The TGT is encrypted using the long-term key shared
	 * between the AS and TGS:
	 *
	 *      Key_AS_TGS.txt
	 *
	 * Encryption:
	 *  - AES-256-ECB (for simplicity in this assignment)
	 *
	 * Output:
	 *  - TGT hex string (stored in memory for next step)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_AS_TGS.txt (hex, 32 bytes)
	 *  - Concatenate client ID and Key_Client_TGS hex
	 *  - AES-encrypt under Key_AS_TGS
	 *  - Hex-encode the ciphertext
	 */

	/* ------------------------------------------------------------
	 * STEP 6: Build AS_REP
	 *
	 * AS_REP plaintext format:
	 *
	 *   [ 32 bytes Key_Client_TGS ] ||
	 *   [ ASCII hex string of TGT ]
	 *
	 * Encrypt AS_REP using:
	 *
	 *      Key_Client_AS
	 *
	 * Output file:
	 *      "AS_REP.txt"   (hex ciphertext)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Concatenate raw Key_Client_TGS and TGT hex string
	 *  - AES-256 encrypt using Key_Client_AS
	 *  - Hex-encode ciphertext
	 *  - Write to AS_REP.txt (single line)
	 */

	return EXIT_SUCCESS;
}
