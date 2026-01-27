**Main Progams** 
  - Projects designed to demonstrate understading of cybersecurity concepts
  - Programs that involved the most development time

    **DigitalSignatureViaHash Program**
    - To run, navigate to VerifySolution folder in terminal
    - Run following command in terminal 
    ```bash VerifyingYourSolution1.sh```
    **Program Description**
    Alice reads the message from the "Message.txt" file and the shared seed from the "SharedSeed.txt" file. The secret key is then generated from the shared seed by utilizing the ChaCha20 PRNG function from OpenSSL. The key size matches the message length. The Hex format of the key is written in a file named "Key.txt". The message is XOR'd with the secret key to obtain the ciphertext: (Ciphertext = Message XOR Key). The Hex format of the ciphertext is written in a file named "Ciphertext.txt". Once Bob has processed the message, Alice reads Bob's computed hash from "Hash.txt". If the comparison is successful, Alice can be confident that Bob has received the accurate message. She then writes "Acknowledgment Successful" in a file called "Acknowledgment.txt." Conversely, if the comparison fails,she records "Acknowledgment Failed."

    Bob reads the ciphertext from the "Ciphertext.txt" file. The shared seed is read from the "SharedSeed.txt" file. The secret key is generated from the shared seed by utilizing the PRNG function from OpenSSL. The key size matches the message length. The received ciphertext is XOR'd with the secret key to obtain the plaintext: (plaintext = ciphertext XOR key). The decrypted plaintext is written in a file named "Plaintext.txt". The plaintext is hashed via SHA256 and the Hex format of the hash is written in a file named "Hash.txt" for Alice to verify.


**Support Programs**
  - Side projects built to work towards the larger main projects
