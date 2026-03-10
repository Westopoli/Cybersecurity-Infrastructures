#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Client (File-Based Demo) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files or change their formats.
 *  - The grading scripts rely strictly on these filenames.
 *
 * This program implements the CLIENT SIDE of a simplified
 * Kerberos protocol using files for message passing.
 *
 * The client program is executed multiple times by an
 * external script and must correctly handle different
 * protocol phases depending on which files already exist.
 *
 * ------------------------------------------------------------
 * PROTOCOL PHASES IMPLEMENTED BY THIS CLIENT:
 *
 * 1) AS phase   (Authentication Server)
 * 2) TGS_REQ    (Ticket Granting Service Request)
 * 3) APP_REQ    (Application Server Request)
 *
 * Cryptographic primitives used conceptually:
 *  - ECDSA signatures
 *  - ECDH key agreement
 *  - SHA-256 key derivation
 *  - AES-256 encryption/decryption
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Study them carefully before implementing this file.
 *
 * ============================================================
 */

 /*
 * CLIENT.C - Kerberos Client
 *
 * Invocation: ./client <Client_temp_SK.txt> <Client_temp_PK.txt> <AS_temp_PK.txt>
 *
 * STEP 1 - ARGUMENT CHECK
 *   Verify exactly 3 command-line arguments are provided.
 *   If not, print usage message and exit with EXIT_FAILURE.
 *
 * STEP 2 - VERIFY EPHEMERAL KEY FILES EXIST
 *   Check that Client_temp_SK.txt and Client_temp_PK.txt are present on disk.
 *   If either is missing, print an error and exit.
 *   The client never generates keys; it only uses pre-existing key material.
 *
 * STEP 3 - SIGN THE CLIENT EPHEMERAL PUBLIC KEY (ECDSA)
 *   Load the long-term client signing key from Client_SK.txt.
 *   Sign the contents of Client_temp_PK.txt using ECDSA.
 *   Write the resulting hex-encoded signature to Client_Signature.txt.
 *   This signature lets the KDC authenticate the client.
 *   If signing fails, exit.
 *
 * STEP 4 - WAIT FOR AS RESPONSE
 *   Check if AS_REP.txt exists.
 *   If it does not, print "KDC has not responded yet" and exit successfully.
 *   The verification script will re-invoke the client later.
 *
 * STEP 5 - DERIVE CLIENT-AS SESSION KEY (ECDH + SHA-256)
 *   Compute the ECDH shared secret using Client_temp_SK.txt and AS_temp_PK.txt.
 *   Hash the shared secret with SHA-256 to produce Key_Client_AS.
 *   Compare the derived key byte-for-byte against Key_Client_AS.txt.
 *   If they do not match or the file is unreadable, exit with failure.
 *
 * STEP 6 - DECRYPT THE AS REPLY (AES-256-ECB)
 *   Read the hex ciphertext from AS_REP.txt.
 *   Decrypt it using AES-256-ECB with Key_Client_AS.
 *   Parse the plaintext:
 *     - First 32 bytes = Key_Client_TGS (binary session key)
 *     - Remaining bytes = TGT (hex string)
 *   If plaintext is shorter than 32 bytes, exit with error.
 *
 * STEP 7 - CONSTRUCT TGS REQUEST
 *   If TGS_REQ.txt does not already exist:
 *     Encrypt the string "Client" using AES-256-ECB with Key_Client_TGS
 *     to produce Auth_Client_TGS (hex-encoded authenticator).
 *     Write TGS_REQ.txt with three lines:
 *       Line 1: TGT (hex)
 *       Line 2: Auth_Client_TGS (hex)
 *       Line 3: "Service" (plaintext service identifier)
 *   If any step fails, exit immediately.
 *
 * STEP 8 - WAIT FOR TGS RESPONSE
 *   Check if TGS_REP.txt exists.
 *   If it does not, print a status message and exit successfully.
 *   The verification script will re-invoke the client later.
 *
 * STEP 9 - DERIVE CLIENT-APPLICATION SESSION KEY (AES-256-ECB)
 *   Read line 2 of TGS_REP.txt (encrypted Key_Client_App).
 *   Decrypt it using AES-256-ECB with Key_Client_TGS.
 *   Convert the resulting hex string into a 32-byte binary key.
 *   If the key is invalid or not exactly 32 bytes, exit.
 *
 * STEP 10 - CONSTRUCT APPLICATION REQUEST
 *   Encrypt "Client" using AES-256-ECB with Key_Client_App
 *   to produce Auth_Client_App (hex-encoded).
 *   Read line 1 of TGS_REP.txt to obtain Ticket_App (hex).
 *   Write APP_REQ.txt with two lines:
 *     Line 1: Ticket_App (hex)
 *     Line 2: Auth_Client_App (hex)
 *   Successful write concludes the client-side protocol.
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {

	/* ------------------------------------------------------------
	 * Command-line arguments:
	 *
	 * argv[1] : path to Client temporary private key file
	 * argv[2] : path to Client temporary public key file
	 * argv[3] : path to AS temporary public key file
	 *
	 * These files MUST already exist. Do NOT generate keys here.
	 * ------------------------------------------------------------
	 */
	if (argc != 4) {
		fprintf(stderr,
		        "Usage: %s <Client_temp_SK> <Client_temp_PK> <AS_temp_PK>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_temp_sk_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_pk_path     = argv[3];

	/* Buffers for symmetric keys derived during Kerberos */
	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];
	unsigned char key_client_app[32];

	/* ------------------------------------------------------------
	 * STEP 0: Verify required client temporary key files exist
	 *
	 * The client must already possess a temporary EC key pair.
	 * If either file is missing, abort immediately.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of:
	 *        client_temp_sk_path
	 *        client_temp_pk_path
	 *  - Print an error and exit on failure
	 */
	if(!file_exists(client_temp_sk_path) || !file_exists(client_temp_pk_path)){
		printf("Temporary client EC pair not found.\n");
		return EXIT_FAILURE;
	}
	/* ------------------------------------------------------------
	 * STEP 1: Sign Client temporary public key
	 *
	 * The client authenticates itself to the AS by signing its
	 * temporary public key using its long-term private key.
	 *
	 * INPUT:
	 *  - Client_SK.txt          (long-term client private key)
	 *  - client_temp_pk_path    (temporary public key)
	 *
	 * OUTPUT (must always be regenerated):
	 *  - Client_Signature.txt   (hex-encoded ECDSA signature)
	 *
	 * NOTE:
	 *  - Even if the file already exists, regenerate it.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Use an ECDSA signing helper
	 *  - Sign the CONTENTS of client_temp_pk_path
	 *  - Write the signature in hex format to:
	 *        "Client_Signature.txt"
	 */
	// unsigned char* byte_sk;
	// size_t byte_sk_len;
	// unsigned char* byte_pk;
	// size_t byte_pk_len;
	// hex_to_bytes(client_temp_sk_path, &byte_sk, &byte_sk_len);
	// hex_to_bytes(client_temp_pk_path, &byte_pk, &byte_pk_len);

	if(ecdsa_sign_file_to_hex(client_temp_sk_path, client_temp_pk_path, "Client_Signature.txt") == 0){
		printf("ECDSA signing failed.\n");
		return 1;
	}
	// printf("Result: %d\n", ecdsa_verify_file_from_hex(client_temp_sk_path, client_temp_pk_path, "Client_Signature.txt"));
	
	/* ------------------------------------------------------------
	 * STEP 2: Wait for AS response
	 *
	 * The Authentication Server writes AS_REP.txt when ready.
	 * If it does not yet exist, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check if "AS_REP.txt" exists
	 *  - If not, print a status message and exit SUCCESSFULLY
	 */
	if(file_exists("Correct_AS_REP_1.txt") == 0){	//
		printf("Could not find 'AS_REP.txt'.\n");
		return 0;
	}
	/* ------------------------------------------------------------
	 * STEP 3: Derive Key_Client_AS
	 *
	 * The client derives a shared secret with the AS using ECDH:
	 *
	 *      shared = ECDH(Client_temp_SK, AS_temp_PK)
	 *
	 * Then derives a symmetric key:
	 *
	 *      Key_Client_AS = SHA256(shared)
	 *
	 * This key MUST match the reference key stored in:
	 *      "Key_Client_AS.txt"
	 *
	 * Abort if the derived key does not match.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Perform ECDH using the two key files
	 *  - Hash the shared secret using SHA-256
	 *  - Read "Key_Client_AS.txt" (hex)
	 *  - Compare values byte-for-byte
	 */
	// Compute shared key as client
	unsigned char* shared_secret = NULL;
	size_t shared_secret_len = 0;
	if(ecdh_shared_secret_files(client_temp_sk_path, as_temp_pk_path, &shared_secret, &shared_secret_len) == 0){
		printf("Shared key computation failed.\n");
		return 1;
	}
	sha256_bytes(shared_secret, shared_secret_len, key_client_as);
	free(shared_secret);

	// Obtain shared key from AS
	unsigned char* reference_key = NULL;
	size_t reference_key_len = 0;
	if(read_hex_file_bytes("Correct_Key_Client_AS_1.txt", &reference_key, &reference_key_len) == 0){	//
		printf("Could not read Key_Client_AS_txt.\n");
		return 1;
	}

	// Compare AS and client shared keys
	if(memcmp(key_client_as, reference_key, reference_key_len) != 0){
		printf("The shared keys do not match.\n");
		free(reference_key);
		return 1;
	}
	free(reference_key);
	/* ------------------------------------------------------------
	 * STEP 4: Decrypt AS_REP
	 *
	 * AS_REP.txt is AES-256 encrypted using Key_Client_AS.
	 *
	 * After decryption, the plaintext contains:
	 *
	 *   [ 32 bytes Key_Client_TGS ] ||
	 *   [ ASCII hex string of TGT ]
	 *
	 * Extract BOTH values.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - AES-decrypt AS_REP.txt using Key_Client_AS
	 *  - Copy first 32 bytes → key_client_tgs
	 *  - Remaining bytes → TGT (hex string)
	 */
	// Don't know if AS_REP.txt must be hex or bytes
	unsigned char* as_rep_bytes = NULL;
	size_t as_rep_bytes_len = 0;
	// if(read_hex_file_bytes("Correct_AS_REP_1.txt", &as_rep_bytes, &as_rep_bytes_len) == 0){
	// 	printf("Could not read AS_REP.txt.\n");
	// 	return 1;
	// }
	unsigned char* as_rep_plaintext = NULL;
	size_t as_rep_plaintext_len = 0;
	
	if(aes256_decrypt_hex_file_to_bytes(key_client_as, "Correct_AS_REP_1.txt", &as_rep_plaintext, &as_rep_plaintext_len) == 0){
		printf("Decryption of AS_REP.txt failed.\n");
		return 1;
	}
	
	// Decrypt AS reply, ensure it is 32 bytes or more

	// if(aes256_ecb_decrypt(key_client_as, as_rep_bytes, as_rep_bytes_len, &as_rep_plaintext, &as_rep_plaintext_len) == 0){
	// 	printf("AS_REP decryption failed.\n");
	// 	free(as_rep_bytes);
	// 	return 1;
	// }
	if(as_rep_plaintext_len < 32){
		printf("AS_REP plaintext too short.\n");
		free(as_rep_bytes);
		free(as_rep_plaintext);
		return 1;
	}
	
	// Parse AS reply into session key and TGT
	unsigned char tgt_hex[as_rep_plaintext_len - 32 + 1];
	memcpy(key_client_tgs, as_rep_plaintext, 32);
	// unsigned char* hex = bytes_to_hex(key_client_tgs, 32);
	// printf("key_clinet tgs: %s\n", hex);
	memcpy(tgt_hex, as_rep_plaintext + 32, as_rep_plaintext_len - 32);
	tgt_hex[as_rep_plaintext_len - 32] = '\0';	
	/* ------------------------------------------------------------
	 * STEP 5: Create TGS_REQ (only once)
	 *
	 * If TGS_REQ.txt does NOT already exist:
	 *
	 *   Auth_Client_TGS = AES(Key_Client_TGS, "Client")
	 *
	 * Write TGS_REQ.txt with EXACTLY THREE lines:
	 *
	 *   line 1: TGT hex
	 *   line 2: Auth_Client_TGS hex
	 *   line 3: Service ID string (plain text): "Service"
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REQ.txt"
	 *  - If missing:
	 *      - Encrypt string "Client" using Key_Client_TGS
	 *      - Write all three required lines in order
	 */
	if(file_exists("TGS_REQ.txt") == 0){
		unsigned char* Auth_Client_TGS = NULL;
		int Auth_Client_TGS_len = 0;
		if(aes256_ecb_encrypt(key_client_tgs, "Client", 6, &Auth_Client_TGS, &Auth_Client_TGS_len) == 0){
			printf("'Client' encryption failed.\n");
			return 1;
		}

		// printf("Auth client tgs: %s\n", Auth_Client_TGS);

		unsigned char* Auth_Client_TGS_hex = bytes_to_hex(Auth_Client_TGS, Auth_Client_TGS_len);

		// printf("Hex version: %s\n", Auth_Client_TGS_hex);

		if(write_text_lines("TGS_REQ.txt", tgt_hex, Auth_Client_TGS_hex, "Service") == 0){
			printf("Error with writing to TGS_REQ.txt.\n");
			free(Auth_Client_TGS);
			free(Auth_Client_TGS_hex);
			return 1;
		}
		
		free(Auth_Client_TGS_hex);
		free(Auth_Client_TGS);
	}
   	/* ------------------------------------------------------------
	 * STEP 6: Wait for TGS response
	 *
	 * TGS writes "TGS_REP.txt" when ready.
	 * If missing, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REP.txt"
	 *  - If not present, print status and exit SUCCESSFULLY
	 */
	if(file_exists("Correct_TGS_REP_1.txt") == 0){
		printf("Could not find 'TGS_REP.txt'.\n");
		return EXIT_SUCCESS;
	}
	/* ------------------------------------------------------------
	 * STEP 7: Recover Key_Client_App
	 *
	 * TGS_REP.txt format:
	 *
	 *   line 1: Ticket_App (hex)
	 *   line 2: enc_key_client_app (hex, AES under Key_Client_TGS)
	 *
	 * Decrypt line 2 using Key_Client_TGS to recover:
	 *      Key_Client_App (hex → 32 bytes)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read second line of TGS_REP.txt
	 *  - AES-decrypt using Key_Client_TGS
	 *  - Convert hex string to raw bytes
	 *  - Store exactly 32 bytes in key_client_app
	 */
	unsigned char* enc_key_client_app = read_line("Correct_TGS_REP_1.txt", 2);
	unsigned char* key_client_app_hex = NULL;
	size_t key_client_app_len = 0;
	if(aes256_decrypt_hex_string_to_bytes(key_client_tgs, enc_key_client_app, &key_client_app_hex, &key_client_app_len) == 0){
		printf("Key_Client_App decryption failed.\n");
		free(enc_key_client_app);
		return 1;
	}
	key_client_app_hex[key_client_app_len] = '\0';

	unsigned char* key_client_app_bytes = NULL;
	size_t key_client_app_bytes_len = 0;
	if(hex_to_bytes(key_client_app_hex, &key_client_app_bytes, &key_client_app_bytes_len) == 0){
		printf("Hex-to-byte conversion of key_client_app failed.\n");
	}
	
	// printf("Hex: %s\n", key_client_app_hex);
	// printf("Bytes: %s\n", key_client_app_bytes);

	memcpy(key_client_app, key_client_app_bytes, 32);

	// printf("key client app bytes: %s\n", key_client_app);
	// size_t key_client_app_len = 0;
	// memcpy(key_client_app, key_client_app_bytes, 32);
	// // key_client_app = bytes_to_hex(key_client_app_bytes, key_client_app_bytes_len);
	// unsigned char* key_client_app_hex = bytes_to_hex(key_client_app, key_client_app_bytes_len);
	// printf("key client app: %s\n", key_client_app);
	// printf("lenght: %d\n", key_client_app_bytes_len);
	
	
	/* ------------------------------------------------------------
	 * STEP 8: Create APP_REQ
	 *
	 *   Auth_Client_App = AES(Key_Client_App, "Client")
	 *
	 * Write APP_REQ.txt with EXACTLY TWO lines:
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: Auth_Client_App hex
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Encrypt string "Client" using Key_Client_App
	 *  - Read Ticket_App from TGS_REP.txt (line 1)
	 *  - Write both values to "APP_REQ.txt"
	 */
	
	unsigned char* Auth_Client_App = NULL;
	int Auth_Client_App_len = 0;
	if(aes256_ecb_encrypt(key_client_app, "Client", 6, &Auth_Client_App, &Auth_Client_App_len) == 0){
		printf("Client encryption for APP_REQ.txt failed.\n");
		return 1;
	}
	unsigned char* Auth_Client_App_hex = bytes_to_hex(Auth_Client_App, Auth_Client_App_len);

	unsigned char* ticket_app_hex = read_line("Correct_TGS_REP_1.txt", 1);

	if(write_text_lines("APP_REQ.txt", ticket_app_hex, Auth_Client_App_hex, "") == 0){
		printf("Could not write to APP_REQ.txt.\n");
		free(ticket_app_hex);
		return 1;
	}
	
	free(ticket_app_hex);
	free(enc_key_client_app);
	
	return EXIT_SUCCESS;
}