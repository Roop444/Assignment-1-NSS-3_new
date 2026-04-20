# Secure File Transfer using Kerberos + AES-GCM

## Phase 1 – Authentication

Implemented mutual authentication using Kerberos V5 and GSSAPI.

Client:
- gss_init_sec_context()

Server:
- gss_accept_sec_context()

Only authenticated users can connect.

---

## Phase 2 – Crypto Layer

Used OpenSSL EVP with AES-256-GCM.

Features:
- Random 256-bit AES key
- 12-byte nonce
- 16-byte authentication tag

Provides:
- Confidentiality
- Integrity
- Replay resistance

---

## Phase 3 – Secure Key Establishment

After Kerberos authentication:

1. Client generates random AES key
2. Key securely sent using gss_wrap()
3. Server recovers key using gss_unwrap()

Thus AES key is protected by Kerberos-authenticated context.

---

## Phase 4 – Tamper Detection

MITM proxy flips ciphertext byte.

Result:

Server prints:

TAG VERIFY FAILED

Demonstrates integrity enforcement.

---

## Build

make

## Run Server

./sfc-server

## Run Client

./sfc-client test_file.txt

## Output

received.out
