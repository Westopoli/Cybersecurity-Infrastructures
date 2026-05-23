# Cybersecurity Infrastructures

> Cryptographic protocols and security infrastructure implemented in **C** with **OpenSSL** — symmetric crypto, identity-based crypto, group key agreement, proof-of-work, aggregate authentication, and forensic logging.

**Contributors:** [Westley Yarlott](https://github.com/Westopoli) · [Daniel Zacarias](https://www.linkedin.com/in/daniel-zacarias-018291330)

`C` · `OpenSSL` · `Applied Cryptography` · `Elliptic Curves` · `Security Protocols`

---

## Projects

### [Digital Forensics Tools](Main%20Programs/DigitalForensicsTools) — forward-secure aggregate HMAC logger
Hash-chained aggregate HMAC + AES-CTR encrypted log with offline auditor verification.
`AES-CTR` `HMAC-SHA256` `ChaCha20 PRNG` `Forward Security`

### [Client–Server Puzzle](Main%20Programs/ClientServerPuzzle) — SHA-256 proof-of-work for DoS mitigation
Hash-based PoW protocol: client brute-forces a nonce with `k` leading zero bits, server verifies in O(1).
`SHA-256` `Proof-of-Work` `DoS Mitigation`

### [Digital Signature Via Hash](Main%20Programs/DigitalSignatureViaHash) — ChaCha20 stream cipher + hash ACK
Two-party symmetric channel with SHA-256 acknowledgment over file-IPC.
`ChaCha20 PRNG` `SHA-256` `XOR Stream Cipher`

### [Merkle Hash Tree](Main%20Programs/MerkleHashTree) — SHA-256 binary tree + authentication paths
Eight-leaf MHT with offline root computation and online authentication-path queries for any leaf index.
`SHA-256` `Merkle Tree` `Data Integrity`

### [Hierarchical Identity-Based Signatures](Main%20Programs/HierarchicalIdentityBasedSignatures) — Schnorr-based 2-level HIBS
PKG-issued level-1 keys delegate signing authority to level-2 identities; verification uses identity-derived public keys.
`Elliptic Curves` `Schnorr` `Identity-Based Crypto` `Key Delegation`

### [Arazi–Qi Key Exchange](Main%20Programs/AraziQiKeyExchange) — identity-based authenticated Diffie–Hellman
EC-based IBAKE: CA-derived identity public keys + ephemeral DH = authenticated shared secret without certificate exchange.
`Elliptic Curves` `IBAKE` `Authenticated Key Exchange`

### [Tree Group Diffie–Hellman](Main%20Programs/TreeGroupDiffieHellman) — dynamic group key agreement
Binary key tree supporting setup, join, leave, merge, and refresh — forward/backward secrecy under membership change.
`BIGNUM Modular Exp` `Group Key Agreement` `Diffie–Hellman`

### [Lightweight Chained MAC](Main%20Programs/LightweightChainedMAC) — sequential aggregate HMAC <sub>*(in debug)*</sub>
Chained HMAC where each tag depends on the previous, yielding one O(1) aggregate tag for N messages.
`HMAC-SHA256` `Aggregate Authentication` `Chained MAC`

### [Condensed RSA](Main%20Programs/CondensedRSA) — RSA-homomorphism aggregate signatures
Exploits RSA's multiplicative homomorphism to compress *j* signatures into a single same-size aggregate.
`RSA` `Aggregate Signatures` `Homomorphic`

---

## Detailed Project Descriptions

### Digital Forensics Tools
> Forward-secure, aggregate HMAC logger with AES-CTR encryption and an offline auditor.

`C` `OpenSSL` `AES-CTR` `HMAC-SHA256` `ChaCha20 PRNG` `Forward Security`

**Objective**

Implements a two-binary system — [`alice.c`](Main%20Programs/DigitalForensicsTools/alice.c) (logging machine) and [`bob.c`](Main%20Programs/DigitalForensicsTools/bob.c) (auditor) — that delivers compromise-resilient encryption, integrity, and authentication with O(1) aggregate tag size.

**Implementation Strategy**

Alice expands a shared seed via ChaCha20 PRNG into the initial 32-byte key, then for each message: encrypts with AES-CTR, computes an HMAC-SHA256 individual tag, folds it into the running aggregate via `S(1,i) = SHA256(S(1,i-1) || S(i))`, and ratchets the key forward with `k(i+1) = SHA256(k(i))`. Bob re-derives keys from the same seed, recomputes the aggregate, and decrypts only if the aggregate matches.

**Files**
- [`alice.c`](Main%20Programs/DigitalForensicsTools/alice.c) — logger / writer
- [`bob.c`](Main%20Programs/DigitalForensicsTools/bob.c) — auditor / verifier
- [`VerifySolution/`](Main%20Programs/DigitalForensicsTools/VerifySolution) — test vectors + harness

**Build & Verify**
```bash
# from within VerifySolution/
bash VerifyYourSolution3.sh
```

---

### Client–Server Puzzle
> Hash-based proof-of-work that gates server resources behind client compute.

`C` `OpenSSL` `SHA-256` `Proof-of-Work` `DoS Mitigation`

**Objective**

A three-binary protocol — [`server.c`](Main%20Programs/ClientServerPuzzle/server.c), [`client.c`](Main%20Programs/ClientServerPuzzle/client.c), [`verify.c`](Main%20Programs/ClientServerPuzzle/verify.c) — that forces clients to perform computational work before service is granted, raising the cost of large-scale DoS.

**Implementation Strategy**

Server emits a challenge `(timestamp || nonce)` and difficulty `k`. Client iterates over nonces computing `SHA256(challenge || nonce)` until the hash has `k` leading zero bits, then ships the nonce. Verifier recomputes the hash once and accepts iff the bit condition holds — solve cost is `O(2^k)`, verify cost is `O(1)`.

**Files**
- [`server.c`](Main%20Programs/ClientServerPuzzle/server.c) — puzzle generator
- [`client.c`](Main%20Programs/ClientServerPuzzle/client.c) — brute-force solver
- [`verify.c`](Main%20Programs/ClientServerPuzzle/verify.c) — solution verifier

**Build & Verify**
```bash
# from within VerifySolution/
bash VerifyYourSolutionClientPuzzle.sh
```

---

### Digital Signature Via Hash
> Symmetric channel between two parties with SHA-256–based acknowledgment.

`C` `OpenSSL` `ChaCha20 PRNG` `SHA-256` `XOR Stream Cipher`

**Objective**

Two-party communication system using a PRNG-derived one-time stream cipher: Alice encrypts a message, Bob decrypts and proves receipt via a SHA-256 hash that Alice verifies.

**Implementation Strategy**

Both parties share a 32-byte seed. Alice expands the seed via ChaCha20 PRNG into a keystream matching the message length, XORs plaintext with the keystream to produce ciphertext, and writes ciphertext to disk. Bob reads the ciphertext, expands the same seed, recovers the plaintext, and writes `SHA256(plaintext)`. Alice compares Bob's hash against her own computed hash and writes "Acknowledgment Successful" or "Acknowledgment Failed".

**Files**
- [`alice.c`](Main%20Programs/DigitalSignatureViaHash/alice.c) — sender
- [`bob.c`](Main%20Programs/DigitalSignatureViaHash/bob.c) — receiver

**Build & Verify**
```bash
# from within VerifySolution/
bash VerifyingYourSolution.sh
```

---

### Merkle Hash Tree
> Eight-leaf binary hash tree with O(log n) authentication paths.

`C` `OpenSSL` `SHA-256` `Merkle Tree` `Data Integrity`

**Objective**

Single binary, [`mht.c`](Main%20Programs/MerkleHashTree/mht.c), builds an 8-leaf Merkle Hash Tree over 32-byte messages, emits the root, and produces the authentication path for any chosen leaf index.

**Implementation Strategy**

Each leaf is `SHA256(message)`. Internal nodes are `SHA256(left || right)`. The root is written to `TheRoot.txt`. For a requested leaf index, the program walks from leaf to root, emitting each visited node's sibling hash into `ThePath.txt` — the receiver can re-derive the root by hashing along the path.

**Files**
- [`mht.c`](Main%20Programs/MerkleHashTree/mht.c) — tree construction + authentication path

**Build & Verify**
```bash
# from within VerifySolution/
bash VerifyYourSolutionMHT.sh
```

---

### Hierarchical Identity-Based Signatures
> Two-level Schnorr-based HIBS with PKG → level-1 → level-2 key delegation.

`C` `OpenSSL` `Elliptic Curves` `Schnorr` `Identity-Based Crypto`

**Objective**

A four-binary HIBS suite — [`pkg.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/pkg.c), [`signer1.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/signer1.c), [`signer2.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/signer2.c), [`verifier.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/verifier.c) — implementing setup, level-1 extract, level-2 extract + sign, and verify.

**Implementation Strategy**

PKG samples master secret `x`, publishes master public `mpk = x·P`. Level-1 extract: `Q_ID1 = b1·P`, `c_ID1 = H(ID_1 || Q_ID1)`, `sk_ID1 = x·c_ID1 + b1 mod q`. Level-2 extract delegates similarly from `sk_ID1`. Signing follows Schnorr: commit `R = r·P`, hash `h = H(m || R)`, respond `s = r + h·sk`. Verify reconstructs the effective public key `PK_eff` from identity hashes and checks `s·P ?= R + h·PK_eff`.

**Files**
- [`pkg.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/pkg.c) — master key generation
- [`signer1.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/signer1.c) — level-1 key extraction
- [`signer2.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/signer2.c) — level-2 extraction + signing
- [`verifier.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/verifier.c) — signature verification
- [`RequiredFunctions.c`](Main%20Programs/HierarchicalIdentityBasedSignatures/RequiredFunctions.c) / [`.h`](Main%20Programs/HierarchicalIdentityBasedSignatures/RequiredFunctions.h) — EC helpers

**Build & Verify**
```bash
# from within TestVectors/
bash VerifyHIBS.sh
```

---

### Arazi–Qi Key Exchange
> Identity-based authenticated Diffie–Hellman on elliptic curves — no certificate exchange.

`C` `OpenSSL` `Elliptic Curves` `IBAKE` `Authenticated Key Exchange`

**Objective**

A three-binary IBAKE protocol — [`ca.c`](Main%20Programs/AraziQiKeyExchange/ca.c), [`alice.c`](Main%20Programs/AraziQiKeyExchange/alice.c), [`bob.c`](Main%20Programs/AraziQiKeyExchange/bob.c) — that derives an authenticated shared secret between identities without exchanging certificates.

**Implementation Strategy**

CA holds master secret `d`, publishes `D = d·P`. For each identity `ID`, CA issues `U = b·P`, `h = H(ID || U)`, `x = (h·b + d) mod q`. Alice/Bob compute ephemeral keys `E = p·P` and exchange. Each side derives `K_ab = x_a·(h_B·U_b + D) + p_a·E_b` (and the symmetric version on Bob's side) — both arrive at the same shared secret, with implicit authentication from the identity-binding term.

**Files**
- [`ca.c`](Main%20Programs/AraziQiKeyExchange/ca.c) — Certification Authority master setup + per-user issuance
- [`alice.c`](Main%20Programs/AraziQiKeyExchange/alice.c) — party A
- [`bob.c`](Main%20Programs/AraziQiKeyExchange/bob.c) — party B
- [`RequiredFunctions.c`](Main%20Programs/AraziQiKeyExchange/RequiredFunctions.c) / [`.h`](Main%20Programs/AraziQiKeyExchange/RequiredFunctions.h) — EC helpers

**Build & Verify**
```bash
# from within TestVectors/
bash VerifyAraziQi.sh
```

---

### Tree Group Diffie–Hellman
> Binary-tree group key agreement supporting dynamic membership.

`C` `OpenSSL` `BIGNUM` `Group Key Agreement` `Diffie–Hellman`

**Objective**

A five-binary TGDH suite — [`setup.c`](Main%20Programs/TreeGroupDiffieHellman/setup.c), [`join.c`](Main%20Programs/TreeGroupDiffieHellman/join.c), [`leave.c`](Main%20Programs/TreeGroupDiffieHellman/leave.c), [`merge.c`](Main%20Programs/TreeGroupDiffieHellman/merge.c), [`refresh.c`](Main%20Programs/TreeGroupDiffieHellman/refresh.c) — that maintains a shared group key across membership change while preserving forward and backward secrecy.

**Implementation Strategy**

Each group member is a leaf in a binary key tree. A leaf holds secret `sk_i`; the tree recurrence is `sk_node = BK_left ^ K_right mod p` where `BK = g^sk mod p` is the blinded key. The group key is the value at the root. Setup builds the initial tree from member secrets and parameters `(p, g)`. Join inserts a new leaf and the sponsor recomputes affected internal keys. Leave promotes the sibling and the sponsor reruns the same key-up-the-co-path computation. Refresh rotates a leaf's secret; merge concatenates two groups' leaf sets and rebuilds.

**Files**
- [`setup.c`](Main%20Programs/TreeGroupDiffieHellman/setup.c) — initial group key
- [`join.c`](Main%20Programs/TreeGroupDiffieHellman/join.c) — add member
- [`leave.c`](Main%20Programs/TreeGroupDiffieHellman/leave.c) — remove member
- [`merge.c`](Main%20Programs/TreeGroupDiffieHellman/merge.c) — combine two groups
- [`refresh.c`](Main%20Programs/TreeGroupDiffieHellman/refresh.c) — rotate a leaf secret
- [`tgdh_shared.c`](Main%20Programs/TreeGroupDiffieHellman/tgdh_shared.c) — tree primitives
- [`RequiredFunctionsTGDH.c`](Main%20Programs/TreeGroupDiffieHellman/RequiredFunctionsTGDH.c) — BIGNUM / file-IO helpers

**Build & Verify**
```bash
# from within TreeGroupDiffieHellman/
bash VerifyingYourSolutionTGDH.sh
```

---

### Lightweight Chained MAC
> Sequential HMAC chain producing one O(1) aggregate tag for N messages.

`C` `OpenSSL` `HMAC-SHA256` `Aggregate Authentication` `Chained MAC`

> **Status.** Source ([`lc_umac.c`](Main%20Programs/LightweightChainedMAC/lc_umac.c)) compiles cleanly, but file output does not yet match the expected test vectors — actively being debugged.

**Objective**

Implements a lightweight chained MAC: each per-message tag is computed under a chained key, and an aggregate tag is folded across messages, yielding constant-size authentication for a sequence of N messages.

**Files**
- [`lc_umac.c`](Main%20Programs/LightweightChainedMAC/lc_umac.c) — LCMAC implementation
- [`TestVectors/`](Main%20Programs/LightweightChainedMAC/TestVectors) — message/seed inputs and expected outputs
- [`VerifyYourLCMACSolution.sh`](Main%20Programs/LightweightChainedMAC/VerifyYourLCMACSolution.sh) — build + run harness

**Build & Verify**
```bash
# from within TestVectors/
bash VerifyYourLCMACSolution.sh
```

---

### Condensed RSA
> Aggregate RSA signatures via multiplicative homomorphism — *j* signatures compressed to one.

`C` `OpenSSL` `RSA` `Aggregate Signatures` `Homomorphic`

**Objective**

Single binary, [`rsaCommented.c`](Main%20Programs/CondensedRSA/rsaCommented.c), produces both individual RSA signatures and a single condensed aggregate over a set of messages.

**Implementation Strategy**

For each message `m_i`, compute `h_i = H(m_i)` and `sig_i = h_i^d mod n`. The condensed signature is the product `agg = ∏ sig_i mod n` — same size as a single signature regardless of `j`. Verification: compute `∏ h_i mod n` and check `agg^e ≡ ∏ h_i (mod n)`. This exploits RSA's multiplicative homomorphism `(a·b)^d = a^d · b^d mod n`.

**Files**
- [`rsaCommented.c`](Main%20Programs/CondensedRSA/rsaCommented.c) — showcase implementation with verbose explanatory comments
- [`TestVectors/`](Main%20Programs/CondensedRSA/TestVectors) — RSA parameters, messages, expected signatures
- [`VerifyYourCRSASolution.sh`](Main%20Programs/CondensedRSA/VerifyYourCRSASolution.sh) — build + run harness

**Build & Verify**
```bash
# from within TestVectors/
bash VerifyYourCRSASolution.sh
```

---

## Repository Layout

```
Main Programs/                          # All showcase projects
├── DigitalForensicsTools/              # Forward-secure aggregate HMAC + AES-CTR
├── ClientServerPuzzle/                 # SHA-256 PoW
├── DigitalSignatureViaHash/            # ChaCha20 stream cipher + hash ACK
├── MerkleHashTree/                     # SHA-256 MHT + auth paths
├── HierarchicalIdentityBasedSignatures/# Schnorr 2-level HIBS
├── AraziQiKeyExchange/                 # EC IBAKE
├── TreeGroupDiffieHellman/             # Group key agreement
├── LightweightChainedMAC/               # Chained HMAC (in debug)
└── CondensedRSA/                       # RSA aggregate signatures

CyberInfra-PnP-Mac/                     # VirtualBox unattended-install automation
```

## Build Requirements

- C compiler (`gcc` or `clang`)
- OpenSSL development headers (`libssl-dev` / `openssl@3` on macOS via Homebrew)
- POSIX shell for verify scripts (`bash`)

Each project links against `-lcrypto` from OpenSSL.
