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
   - Generate random 128-bit symmetric key
   - Encrypt symmetric key with sender's RSA public key using EME1(SHA-256)
   - Sign encrypted key with receiver's pre-shared private key using PSS(SHA-256)
   - Send: [encrypted key] + [signature] + [signature size (2 bytes)]

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
- `get_public_key()` – Verify sender's public key signature
- `send_symmetric_key()` – Generate, encrypt, and sign symmetric key
- `receive_periodic_messages()` – Verify CMAC on incoming messages

### Vector Usage

The code uses `std::vector` functionality for safe, idiomatic C++ memory management:
- `vector::assign()` – Copy data from iterators
- `vector::insert()` – Append data to vectors
- Iterator-based operations avoid raw `std::memcpy()` calls

## Security Considerations

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

