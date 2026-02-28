**Main Programs**

  **Digital Signature Via Hash Program - Output Feedback Mode**
  - To run, navigate to VerifySolution folder in terminal
  - Run following command in terminal:
  ```bash VerifyingYourSolution1.sh```
   
  **Client Server Puzzle Program - DDoS Prevention**
  - To run, navigate to VerifySolution folder in terminal
  - Run following command in terminal:
  ```bash VerifyYourSolutionClientPuzzle.sh```

  **Merkle Hash Tree Program**
  - To run, navigate to VerifySolution folder in terminal
  - Run following command in terminal:
  ```bash VerifyYourSolutionMHT.sh```

  **Forward-Secure and Aggregate Digital Forensics Tools - CIA - Military Grade Software**
  - To run, navigate to VerifySolution folder in terminal
  - Run following command in terminal:
  ```bash VerifyYourSolution3.sh```


**Support Programs**
  - Side projects built to work towards the larger main projects


**Program Descriptions** 

  **Digital Signature Via Hash Program**
  
Alice reads the message from the "Message.txt" file and the shared seed from the "SharedSeed.txt" file. The secret key is then generated from the shared seed by utilizing the ChaCha20 PRNG function from OpenSSL. The key size matches the message length. The Hex format of the key is written in a file named "Key.txt". The message is XOR'd with the secret key to obtain the ciphertext: (Ciphertext = Message XOR Key). The Hex format of the ciphertext is written in a file named "Ciphertext.txt". Once Bob has processed the message, Alice reads Bob's computed hash from "Hash.txt". If the comparison is successful, Alice can be confident that Bob has received the accurate message. She then writes "Acknowledgment Successful" in a file called "Acknowledgment.txt." Conversely, if the comparison fails,she records "Acknowledgment Failed."
      
Bob reads the ciphertext from the "Ciphertext.txt" file. The shared seed is read from the "SharedSeed.txt" file. The secret key is generated from the shared seed by utilizing the PRNG function from OpenSSL. The key size matches the message length. The received ciphertext is XOR'd with the secret key to obtain the plaintext: (plaintext = ciphertext XOR key). The decrypted plaintext is written in a file named "Plaintext.txt". The plaintext is hashed via SHA256 and the Hex format of the hash is written in a file named "Hash.txt" for Alice to verify.

  **Client Server Puzzle Program**

C implementation of a Client–Server Proof-of-Work protocol designed to mitigate Denial-of-Service (DoS) attacks. The project includes puzzle generation, brute-force solving, and secure verification using SHA256 from OpenSSL.
  
The Server reads the challenge from the "Challenge$i.txt" file. The challenge consists of a 32-byte value representing (timestamp || server nonce). The difficulty level k is read from the "Difficulty$i.txt" file as an ASCII integer. The Server writes the Hex format of the challenge to a file named "puzzle challenge.txt" and writes the difficulty k to a file named "puzzle k.txt". This challenge is broadcast to the Client.

The Client reads the challenge from the "puzzle challenge.txt" file and the difficulty value k from the "puzzle k.txt" file. The Client performs a brute-force search starting from nonce = 0. For each nonce, the Client constructs (challenge || nonce) and computes the SHA256 hash using OpenSSL. The Client checks whether the first k leading bits of the hash are zero. This process continues until a valid nonce is found. Once a solution is discovered, the Hex format of the nonce (8 bytes) is written to "solution nonce.txt" and the total number of iterations required is written to "solution iterations.txt".

The Verify program (Server-side verification) reads the challenge from "puzzle challenge.txt", the difficulty k from "puzzle k.txt", and the nonce from "solution nonce.txt". It reconstructs (challenge || nonce) and recomputes the SHA256 hash using OpenSSL. The program checks whether the hash contains k leading zero bits. If the condition is satisfied, the program writes "ACCEPT" to "verification result.txt" and exits successfully. If the condition fails, the program writes "REJECT" to "verification result.txt" and terminates.

This implementation demonstrates a hash-based Proof-of-Work mechanism that forces clients to perform computational effort before service is granted, thereby increasing the cost of large-scale automated Denial-of-Service (DoS) attacks.

  **Merkle Hash Tree Program**

The program reads 8 newline-separated 32-byte lines of data from either the "Messages1.txt" or "Messages2.txt" file. It uses SHA256 to hash each line of data to obtain values of the leaves of the Merkle Hash Tree (MHT), then calculates the remaining nodes by concatenating their children's hashes from left to right and hashing the result. The root of the resulting MHT is converted to hex and written to "TheRoot.txt" file. 

The program also reads a user-inputted message index and calculates the verification path for that index. Starting at the message index leaf and going up each level through the parent and ending at the root, the hash value of path node's sibling is converted to hex format and added to the path and separated by a newline character. The verification path is written to "ThePath.txt" file.

