# Secure Communication with Authentication

Establishing a secure and authenticated bidirectional communication channel between a sender and receiver using RSA key exchange, digital signatures, and symmetric key encryption with message authentication codes (CMAC).

## Overview

This project implements a cryptographic communication protocol using POSIX message queues for inter-process communication. It demonstrates:

1. **RSA Public Key Exchange** – Sender generates an RSA key pair and signs the public key with a pre-shared private key
2. **Signature Verification** – Receiver validates the sender's public key using a pre-shared public key
3. **Symmetric Key Encryption** – Receiver generates and encrypts a random symmetric key using the sender's RSA public key, then signs it
4. **Message Authentication** – Periodic messages are protected with CMAC(AES-128) for authenticity and integrity

## Architecture

### Components

- **sender/** – Generates RSA keys, receives and decrypts the symmetric key, sends periodic authenticated messages
- **receiver/** – Validates sender's key, generates and encrypts a symmetric key, receives and verifies messages
- **common/** – Shared configuration constants and message queue definitions

### Message Flow

```
1. SENDER SENDS RSA PUBLIC KEY
   - Generate RSA 2048-bit key pair
   - Sign public key with pre-shared private key using PSS(SHA-256)
   - Send: [DER-encoded public key] + [signature] + [signature size (2 bytes)]

2. RECEIVER VALIDATES & SENDS SYMMETRIC KEY
   - Verify sender's public key signature using pre-shared public key
   - Generate random 128-bit symmetric key (16 bytes)
   - Prepend receiver ID to symmetric key → 17-byte vector [ID byte] + [16-byte key]
   - Encrypt this 17-byte vector with sender's RSA public key using EME1(SHA-256)
   - Sign encrypted key with receiver's pre-shared private key using PSS(SHA-256)
   - Send: [encrypted key] + [signature] + [signature size (2 bytes)]
   - Note: Original 16-byte symmetric key is preserved and returned for use in message authentication

3. SENDER DECRYPTS SYMMETRIC KEY
   - Verify encrypted key signature using receiver's pre-shared public key
   - Decrypt symmetric key using RSA private key

4. SENDER SENDS PERIODIC MESSAGES
   - Message format: [20-byte data] + [16-byte CMAC]
   - CMAC computed using CMAC(AES-128) with shared symmetric key
   - Send 10 messages at 1-second intervals
   - Receiver verifies each message's CMAC
```

## Configuration

All configuration is defined in `common/common.hpp`:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `kMessageSize` | 1024 bytes | Max POSIX message queue message size |
| `kBufferSize` | 20 bytes | Periodic message data size |
| `kCmacSize` | 16 bytes | AES-128 CMAC output size |
| `kSymKeySize` | 16 bytes | AES-128 symmetric key size |
| `kNumMessagesToSend` | 10 | Number of periodic messages |
| `kSendPeriod` | 1000 ms | Interval between messages |

## Cryptographic Primitives

### Algorithms

- **Asymmetric Encryption:** RSA-2048 with EME1(SHA-256) OAEP padding
- **Digital Signatures:** RSA-2048 with PSS(SHA-256) PKCS#1 v2.1
- **Symmetric Encryption:** AES-128
- **Authentication Code:** CMAC(AES-128)
- **Hash Function:** SHA-256

### Botan Library

Uses [Botan 3.10.0](https://botan.randombit.net/) for all cryptographic operations:
- X.509 key serialization (DER/PEM)
- RSA key generation and operations
- Message authentication and signing
- Random number generation

## Build & Run

### Prerequisites

- C++17 compiler (g++, clang++, or MSVC)
- Botan 3.10.0 cryptography library
- POSIX message queue support (Linux/Unix)

### Build

```bash
make
```

Executables are generated in `output/`:
- `output/sender`
- `output/receiver`

### Run

Terminal 1 (Receiver):
```bash
./output/receiver
```

Terminal 2 (Sender):
```bash
./output/sender
```

The receiver waits for the sender to initiate the protocol. Both processes exchange keys and messages via POSIX message queues.

## Implementation Details

### Key Classes & Functions

**sender.cpp:**
- `send_public_key()` – Sign and transmit RSA public key
- `receive_symmetric_key()` – Verify and decrypt symmetric key from receiver
- `send_periodic_message()` – Compute CMAC and send authenticated messages

**receiver.cpp:**
- `get_public_key()` – Verify sender's public key signature; remove prepended ID byte before DER loading (critical for correct key deserialization)
- `send_symmetric_key()` – Generate 16-byte symmetric key; prepend ID to create 17-byte vector; encrypt and sign; return 16-byte key unchanged
- `receive_periodic_messages()` – Verify CMAC on incoming messages using the 16-byte symmetric key

### Vector Usage & Memory Management

The code uses `std::vector` functionality for safe, idiomatic C++ memory management:
- `vector::assign()` – Copy data from iterators for safe data movement
- `vector::insert()` and `vector::erase()` – Modify vectors safely without raw pointers
- Pre-allocation – Allocate exact size when known (e.g., 17-byte temporary vector for ID + symmetric key) to avoid unnecessary reallocations
- Iterator-based operations – Use `std::copy()` and iterators instead of raw `std::memcpy()` calls
- Secure erasure – Clear sensitive data with `std::fill()` after use to prevent memory disclosure

**Key Implementation Detail:** The `send_symmetric_key()` function demonstrates best practices:
- Input/output contract: 16-byte symmetric key in, 16-byte symmetric key out
- Separate temporary 17-byte vector created for [ID byte] + [symmetric key] to avoid modifying the input parameter
- This maintains clear separation of concerns and prevents accidental parameter modification

## Bug Fixes & Implementation Notes

### DER Deserialization Fix
**Issue:** In `get_public_key()`, after removing the prepended ID byte with `erase()`, the size parameter passed to `DataSource_Memory` must be adjusted.
- `der_data.erase(der_data.begin())` removes 1 byte from the vector
- Size parameter must be `der_size - 1` (not `der_size`) to avoid reading beyond valid data
- This ensures the DER parser correctly deserializes the RSA public key

### Symmetric Key Handling
**Design Decision:** The receiver generates a 16-byte symmetric key for CMAC computation. Before encryption:
1. A separate 17-byte temporary vector is created: `[receiver_id_byte] + [16-byte_key]`
2. This 17-byte vector is encrypted and signed
3. The original 16-byte symmetric key is preserved unchanged
4. This pattern ensures:
   - Clear input/output contract for function parameters
   - No accidental modification of data used for MAC operations
   - Proper separation of the key transport layer from the authentication layer

## Security Considerations

### ID Binding in Signatures & Encryption

**Purpose:** Prepending entity IDs to data before signing or encrypting creates a cryptographic binding between the data and the intended recipient/sender. This prevents several attack vectors:

**Sender ID Binding (sender → receiver public key):**
- Public key data is prepended with `kIdSender (0xAA)` before signing
- Signature verifies: `SIGN(sender_id || DER_public_key)`
- **Security Benefit:** Ensures the signature is for this specific sender, not for another sender
- **Attack Prevented:** Signature substitution – attacker cannot take sender A's public key signature and claim it as sender B's key

**Receiver ID Binding (receiver → encrypted symmetric key):**
- Symmetric key is prepended with `kIdReceiver (0xBB)` before encryption: `[0xBB] + [16-byte_key]`
- This 17-byte vector is encrypted: `RSA_ENCRYPT(receiver_id || symmetric_key)`
- Then signed: `SIGN(encrypted_key)`
- **Security Benefit:** Receiver's ID is cryptographically bound to the symmetric key
- **Attack Prevented:** 
  1. **Cross-recipient message injection** – In a multi-party system, attacker cannot redirect receiver A's encrypted key to receiver B (the decrypted key would have wrong ID)
  2. **Symmetric key confusion** – Ensures the decrypted key is bound to the receiver who generated it

**Practical Example of Attack Prevented:**
```
Scenario: 3 endpoints (Sender, ReceiverA, ReceiverB)

Without ID Binding:
1. Sender encrypts symmetric_key with ReceiverA's RSA key
2. Attacker intercepts and redirects to ReceiverB
3. ReceiverB decrypts successfully using own private key (if RSA key reuse)
4. ReceiverB now has wrong key, gets confused state

With ID Binding:
1. Sender encrypts [0xBB_A || symmetric_key] with ReceiverA's RSA key
2. Attacker redirects to ReceiverB
3. ReceiverB decrypts: [0xBB_A || symmetric_key]
4. ReceiverB checks ID: 0xBB_A ≠ 0xBB_B (own ID)
5. ReceiverB rejects message, attack detected
```

**Implementation in Code:**
- **sender.cpp line 90:** `der.insert(der.begin(), static_cast<uint8_t>(kIdSender));`
- **receiver.cpp line 263:** `symmetric_key_with_id[0] = static_cast<uint8_t>(kIdReceiver);`
- **receiver.cpp line 313:** Sender verifies receiver ID matches: `if (symmetric_key_secure[0] != static_cast<uint8_t>(kIdReceiver))`

**Limitation (Two-Party System):**
This protocol is designed for a fixed sender-receiver pair. In a true multi-party system, you would need:
- Dynamic endpoint IDs (not hardcoded constants)
- Per-message sender/receiver fields
- Verify IDs match expected parties before processing

**Recommendation for Students:**
Extend the protocol to support 3+ parties:
1. Add sender_id and receiver_id fields to messages
2. Include them in CMAC calculation: `CMAC_input = [sender_id][receiver_id][counter][payload]`
3. Verify IDs match before accepting messages
4. This provides explicit party binding in addition to implicit ID binding in signatures

- **Pre-shared Keys:** Sender and receiver have pre-configured RSA key pairs for mutual authentication
- **Random Symmetric Key:** Generated fresh each session using `AutoSeeded_RNG`
- **Message Integrity:** CMAC prevents tampering with periodic messages
- **Secure Erasure:** Sensitive data (symmetric keys, signatures) cleared with `std::fill()` after use
- **No Hardcoded Secrets in Production:** Pre-shared keys are embedded for demo; use secure key management in production

## Testing

Run both sender and receiver processes simultaneously. Output includes:
- Hex dumps of keys and signatures for verification
- Success/failure messages for cryptographic operations
- Sent/received message counts and CMACs

## Cryptographic Analysis

This section analyzes the cryptographic design choices for educational purposes.

### Key Exchange Analysis

**RSA-2048 Public Key Exchange**
- **Strength:** 2048-bit RSA provides ~112-bits of symmetric strength (adequate for legacy systems; NIST recommends 2048-bit minimum until 2030)
- **Weakness:** RSA is slow; modern designs use ECDH (e.g., Curve25519) for key exchange
- **Educational Value:** Demonstrates asymmetric encryption fundamentals and X.509 DER encoding
- **Production Concern:** Subject to Shor's algorithm on quantum computers; quantum-resistant alternatives (Kyber, Dilithium) should be considered

**Pre-shared Authentication Keys**
- **Strength:** Mutual authentication via embedded private keys prevents man-in-the-middle attacks
- **Weakness:** Out-of-band key distribution required; keys hardcoded in code (security anti-pattern)
- **Educational Value:** Shows how pre-shared secrets enable entity authentication
- **Production Improvement:** Use PKI with certificate authorities (CAs) and certificate pinning instead

### Symmetric Encryption Analysis

**AES-128**
- **Strength:** AES is NIST-approved; 128-bit keys sufficient for most applications (2^128 brute force is infeasible)
- **Note:** No explicit encryption mode used in this example (symmetric key is just transmitted and verified). In production, would need authenticated encryption (AES-GCM or ChaCha20-Poly1305)
- **Educational Value:** Demonstrates random symmetric key generation and secure key transport
- **Missing:** Encryption of periodic messages—only CMAC authentication used. Should add AES-GCM or similar for confidentiality + integrity

### Digital Signature Analysis

**RSA-PSS(SHA-256)**
- **Strength:** PSS (Probabilistic Signature Scheme) is more secure than PKCS#1 v1.5; includes salt for randomness
- **Weakness:** RSA signatures are large (~256 bytes for 2048-bit RSA); slower than ECDSA
- **Educational Value:** Shows how signatures prove authenticity without encryption
- **Alternative:** EdDSA (Ed25519) offers shorter signatures and better performance; recommended for new designs

**Double-Signature Pattern**
- **Why It's Used Here:**
  - Sender signs public key with pre-shared private key → proves sender's identity
  - Receiver signs encrypted key with pre-shared private key → proves receiver's identity
- **Strength:** Mutual authentication established before symmetric key use
- **Teaching Point:** Demonstrates how signatures can authenticate both endpoints

### Message Authentication (CMAC) Analysis

**CMAC(AES-128)**
- **Strength:** NIST-approved; provides 128-bit authentication tags; secure against forgery
- **Educational Value:** Shows how MACs ensure message integrity without encryption (confidentiality not provided)
- **When to Use:** CMAC when only integrity/authenticity needed; use AEAD (AES-GCM, ChaCha20-Poly1305) for confidentiality + integrity
- **Note:** In this example, periodic messages are sent in **plaintext with CMAC**—contents are visible but tamper-evident. For confidential messages, encrypt first, then MAC (encrypt-then-MAC pattern)

### Protocol Design Analysis

**Strengths:**
1. **Sequential Authentication:** Public key validated before symmetric key exchange
2. **Mutual Authentication:** Both parties sign their contributions
3. **Perfect Forward Secrecy (PFS):** New symmetric key per session (not maintained across sessions)
4. **Separation of Concerns:** Key exchange, key derivation, and message authentication are distinct phases

**Weaknesses & Improvements for Production:**

| Issue | Current | Production Alternative |
|-------|---------|------------------------|
| **Hardcoded Keys** | Pre-shared keys in code | Use secure key management (HSM, cloud KMS) |
| **No Encryption** | Plaintext periodic messages | Add AES-GCM for confidentiality |
| **Limited Counter Range** | 8-bit counter (0-255, wraps at 256) | 32-bit or 64-bit sequence numbers for longer sessions |
| **No Party IDs** | Messages not bound to sender/receiver | Include sender/receiver IDs in CMAC; prevents cross-endpoint message injection |
| **Static Key Pairs** | Sender's RSA key never changes | Rotate keys regularly (monthly/yearly) |
| **No Key Derivation** | Symmetric key used directly | Use KDF (HKDF) to derive multiple keys (encryption, authentication) |
| **No TLS** | Custom protocol | Use TLS 1.3 (mature, audited, standardized) |
| **Single CMAC Key** | All messages authenticated with same key | Different keys for different message types |
| **Message Size Limit** | Fixed 20-byte payload | Support variable-length messages |

### Teaching Lessons

**What This Example Demonstrates:**

1. ✅ **Asymmetric vs. Symmetric Cryptography**
   - RSA for authentication and key exchange (slower, public/private)
   - AES for symmetric operations (faster, single key)

2. ✅ **Digital Signatures**
   - How RSA-PSS creates unforgeable proofs of identity
   - Signature verification using public keys

3. ✅ **Message Authentication Codes (MACs)**
   - CMAC ensures integrity without encryption
   - Difference between confidentiality and authenticity

4. ✅ **Secure Key Transport**
   - Encrypting the symmetric key before transmission
   - Signing encrypted data for authenticity

5. ✅ **Safe Memory Management in C++**
   - Using `std::vector`, `std::fill()` instead of raw pointers and `std::memcpy()`
   - Automatic cleanup of sensitive data

6. ✅ **Replay Attack Mitigation**
   - Sender embeds an 8-bit message counter at `buffer[19]` (line 203 in sender.cpp)
   - Receiver validates counter with `check_freshness_counter()` (line 119 in receiver.cpp)
   - Uses delta checking: rejects duplicates (delta == 0) and out-of-order messages (delta > 128)
   - Limitation: Counter wraps at 256, so max 128 messages per session before wrapping; production systems use 32/64-bit sequence numbers

7. ✅ **Missing Party Binding** – ⚠️ *Security Gap*
   - CMAC authenticates message **contents only**, not sender/receiver identity
   - **Vulnerability in multi-party scenarios:** In a system with 3+ endpoints, an attacker could:
     - Capture message from Sender A → Receiver B
     - Replay it to Receiver C (message still has valid CMAC)
   - **Mitigation:** Include sender/receiver IDs in CMAC calculation:
     ```
     CMAC_input = [sender_id] [receiver_id] [counter] [payload]
     ```
   - **Why it matters for production:** Prevents cross-endpoint message injection and provides party binding
   - **Current code:** Two-party system (fixed Sender ↔ Receiver), so this gap is **low severity** but poor practice
   - **Exercise for Students:** Modify periodic messages to include 1-byte sender_id (0x01) and receiver_id (0x02), include them in CMAC, and verify on receiver side

**What Production Systems Would Add:**

1. ❌ **TLS Handshake** – Standardized, peer-reviewed protocol instead of custom exchange
2. ❌ **Certificate Validation** – X.509 certificate chains instead of pre-shared keys
3. ❌ **AEAD Cipher** – AES-GCM or ChaCha20-Poly1305 for confidentiality + integrity in one operation
4. ❌ **Key Derivation** – HKDF to derive multiple keys from one shared secret
5. ❌ **Perfect Forward Secrecy** – Ephemeral Diffie-Hellman or ECDH for session keys
6. ❌ **Authenticated Encryption** – Encrypt-then-MAC or built-in AEAD modes
7. ❌ **Extended Sequence Numbers** – 32-bit or 64-bit counters instead of 8-bit

### Recommended Reading

- [NIST Special Publication 800-175B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf) – Guideline for Cryptographic Algorithms
- [RFC 5116](https://tools.ietf.org/html/rfc5116) – CRYPTOGRAPHIC ALGORITHM INTERFACE AND USAGE
- [RFC 8446 (TLS 1.3)](https://tools.ietf.org/html/rfc8446) – Modern reference implementation
- [Serious Cryptography](https://nostarch.com/seriouscryptography) by Jean-Philippe Aumasson – Practical guide to cryptographic design

## License

This project is licensed under the MIT License – see [LICENSE](LICENSE) for details.

**Attribution:** Original implementation by Bo-Göran Wallner (2026), Independent academic contributor

The MIT License permits free use, modification, and distribution, provided that the original copyright notice and license text are included in any derivative works or distributions.

### Third-Party Dependencies

- **Botan 3.10.0** – Released under the Simplified BSD License ([license](https://botan.randombit.net/))
- **POSIX Message Queues** – Part of the POSIX standard library (no license restriction)

