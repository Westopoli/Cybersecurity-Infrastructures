#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Ticket Granting Server (TGS) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files, reorder lines, or alter formats.
 *  - Automated grading scripts depend on strict filenames
 *    and exact file structure.
 *
 * This program implements the Ticket Granting Server (TGS)
 * portion of a simplified, file-based Kerberos protocol.
 *
 * All long-term keys and all session keys are assumed to
 * already exist on disk. The TGS must NOT generate keys.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (TGS PHASE):
 *
 * 1) Receive and parse TGS_REQ
 * 2) Decrypt and validate the Ticket Granting Ticket (TGT)
 * 3) Verify the client authenticator
 * 4) Issue a service ticket (Ticket_App)
 * 5) Encrypt and return Key_Client_App
 *
 * Cryptographic primitives used conceptually:
 *  - AES-256 encryption/decryption (ECB mode in this demo)
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Study them carefully before implementing this file.
 *
 * ============================================================
 */

 /*
 * TGS.C - Ticket Granting Server
 *
 * Invocation: ./tgs <TGS_REQ.txt> <Key_AS_TGS.txt> <Key_Client_TGS.txt>
 *                   <Key_Client_App.txt> <Key_TGS_App.txt>
 *
 * STEP 1 - ARGUMENT CHECK
 *   Verify exactly 5 command-line arguments are provided.
 *   If not, print usage message and exit with EXIT_FAILURE.
 *
 * STEP 2 - WAIT FOR TGS REQUEST
 *   Check if TGS_REQ.txt exists.
 *   If missing, print "TGS_REQ not created" and exit.
 *   The verification script will re-invoke the TGS later.
 *
 * STEP 3 - READ AND DECRYPT THE TGT (AES-256-ECB)
 *   Read the TGT hex string from line 1 of TGS_REQ.txt.
 *   Read Key_AS_TGS from Key_AS_TGS.txt.
 *   Decrypt the TGT using AES-256-ECB with Key_AS_TGS.
 *   Obtain plaintext: clientID || Key_Client_TGS_hex
 *   If decryption fails or plaintext is too short, exit with error.
 *
 * STEP 4 - PARSE CLIENT ID AND CLIENT-TGS KEY
 *   Split the TGT plaintext into:
 *     - clientID (variable-length string prefix)
 *     - Key_Client_TGS_hex (trailing 64-character hex string = 32 bytes)
 *   Convert Key_Client_TGS_hex to binary.
 *   Compare it byte-for-byte against Key_Client_TGS.txt.
 *   Any mismatch or invalid hex terminates the program.
 *
 * STEP 5 - DECRYPT CLIENT AUTHENTICATOR (AES-256-ECB)
 *   Read Auth_Client_TGS (hex) from line 2 of TGS_REQ.txt.
 *   Decrypt it using AES-256-ECB with Key_Client_TGS.
 *   This conceptually verifies the client holds the correct session key.
 *   If decryption fails, exit.
 *
 * STEP 6 - READ THE CLIENT-APPLICATION SESSION KEY
 *   Read the pre-generated Key_Client_App from Key_Client_App.txt.
 *   Store both binary and hex-string forms for use in subsequent steps.
 *   If the key is unreadable or invalid, terminate.
 *
 * STEP 7 - BUILD THE APPLICATION TICKET (AES-256-ECB)
 *   Construct application ticket plaintext as:
 *     Ticket_App_plain = clientID || Key_Client_App_hex
 *   Read Key_TGS_App from Key_TGS_App.txt.
 *   Encrypt Ticket_App_plain using AES-256-ECB with Key_TGS_App.
 *   Hex-encode the result to produce Ticket_App.
 *   If encryption fails, terminate.
 *
 * STEP 8 - ENCRYPT CLIENT-APPLICATION KEY FOR CLIENT (AES-256-ECB)
 *   Encrypt Key_Client_App_hex using AES-256-ECB with Key_Client_TGS.
 *   Hex-encode the result to produce enc_key_client_app.
 *   This lets the client securely receive their app session key.
 *
 * STEP 9 - WRITE TGS REPLY
 *   Write TGS_REP.txt with two lines:
 *     Line 1: Ticket_App (hex)
 *     Line 2: enc_key_client_app (hex)
 *   If file writing fails, exit with error.
 *   Successful completion returns EXIT_SUCCESS.
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {

	/* ------------------------------------------------------------
	 * Command-line arguments (file paths):
	 *
	 * argv[1] : TGS_REQ.txt
	 * argv[2] : Key_AS_TGS.txt
	 * argv[3] : Key_Client_TGS.txt
	 * argv[4] : Key_Client_App.txt
	 * argv[5] : Key_TGS_App.txt
	 *
	 * All files MUST already exist.
	 * The TGS must NOT generate any keys.
	 * ------------------------------------------------------------
	 */
	if (argc != 6) {
		fprintf(stderr,
		        "Usage: %s <TGS_REQ> <Key_AS_TGS> <Key_Client_TGS> <Key_Client_App> <Key_TGS_App>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *tgs_req_path        = argv[1];
	const char *key_as_tgs_path     = argv[2];
	const char *key_client_tgs_path = argv[3];
	const char *key_client_app_path = argv[4];
	const char *key_tgs_app_path    = argv[5];

	/* ------------------------------------------------------------
	 * STEP 0: Wait for TGS request
	 *
	 * If the TGS request file does not yet exist, print:
	 *
	 *      "TGS_REQ not created"
	 *
	 * and exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of tgs_req_path
	 *  - If missing, print required message and exit
	 */

	printf("TGS_REQ received\n");

	/* ------------------------------------------------------------
	 * STEP 1: Read and decrypt the Ticket Granting Ticket (TGT)
	 *
	 * TGS_REQ.txt format:
	 *
	 *   line 1: TGT (hex)
	 *   line 2: Auth_Client_TGS (hex)
	 *   line 3: Service ID (plain text, ignored here)
	 *
	 * The TGT is encrypted under the AS–TGS shared key:
	 *      Key_AS_TGS.txt
	 *
	 * Decrypted TGT plaintext format:
	 *
	 *      clientID || Key_Client_TGS_hex
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read line 1 from TGS_REQ.txt
	 *  - Read Key_AS_TGS.txt (32 bytes)
	 *  - AES-decrypt the TGT
	 *  - Treat the result as ASCII data
	 */

	/* ------------------------------------------------------------
	 * STEP 2: Parse client identity and Key_Client_TGS
	 *
	 * From decrypted TGT plaintext:
	 *  - The LAST 64 characters represent Key_Client_TGS in hex
	 *  - Everything before that is the client ID
	 *
	 * Validate:
	 *  - Key_Client_TGS is exactly 256 bits
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Split decrypted TGT plaintext
	 *  - Convert Key_Client_TGS hex → raw bytes
	 *  - Abort if parsing or conversion fails
	 */

	/* ------------------------------------------------------------
	 * STEP 3: Verify client authenticator
	 *
	 * Auth_Client_TGS is found on line 2 of TGS_REQ.txt.
	 *
	 * It is encrypted using Key_Client_TGS and should
	 * decrypt to a value identifying the client.
	 *
	 * NOTE:
	 *  - For this demo, successful decryption is sufficient.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read line 2 from TGS_REQ.txt
	 *  - AES-decrypt using Key_Client_TGS
	 *  - Treat failure as authentication failure
	 */

	/* ------------------------------------------------------------
	 * STEP 4: Load pre-generated Key_Client_App
	 *
	 * The TGS does NOT generate a new application session key.
	 * Instead, it reads an existing one from:
	 *
	 *      Key_Client_App.txt
	 *
	 * This file must contain exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_Client_App.txt (hex)
	 *  - Validate length
	 *  - Store raw bytes locally
	 */

	/* ------------------------------------------------------------
	 * STEP 5: Build and encrypt Ticket_App
	 *
	 * Ticket_App plaintext format:
	 *
	 *      clientID || Key_Client_App_hex
	 *
	 * Ticket_App is encrypted under the TGS–App shared key:
	 *
	 *      Key_TGS_App.txt
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_TGS_App.txt (32 bytes)
	 *  - Concatenate client ID and Key_Client_App hex
	 *  - AES-encrypt using Key_TGS_App
	 *  - Hex-encode ciphertext → Ticket_App
	 */

	/* ------------------------------------------------------------
	 * STEP 6: Encrypt Key_Client_App for the client
	 *
	 * Encrypt:
	 *
	 *      Key_Client_App_hex
	 *
	 * using:
	 *
	 *      Key_Client_TGS
	 *
	 * Result:
	 *  - enc_key_client_app (hex)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - AES-encrypt Key_Client_App hex using Key_Client_TGS
	 *  - Hex-encode the ciphertext
	 */

	/* ------------------------------------------------------------
	 * STEP 7: Write TGS_REP.txt
	 *
	 * Output file format (EXACT):
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: enc_key_client_app hex
	 *
	 * Filename MUST be:
	 *      "TGS_REP.txt"
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Write exactly two lines to TGS_REP.txt
	 *  - Preserve order and formatting
	 */

	return EXIT_SUCCESS;
}
