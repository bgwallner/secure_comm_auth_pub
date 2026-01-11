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

