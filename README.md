# README.md

## Secure File Channel using Kerberos, GSS-API, AES-GCM and Tamper Detection

**Networks and Systems Security II – Exercise 1**

---

# 1. Project Overview

This project implements a **secure authenticated file transfer channel** between a client and a server using:

* **Kerberos V5** for authentication
* **GSS-API** for security context establishment
* **AES-256-GCM** for authenticated encryption of file contents
* **Tamper Proxy / Relay** for adversarial modification testing

The objective is to demonstrate that:

1. Only an authenticated Kerberos user can initiate transfer.
2. The client securely binds file encryption to the Kerberos-authenticated session.
3. File contents remain confidential in transit.
4. Any modification in transit is detected.
5. The receiver safely rejects tampered data without writing corrupted output.

---

# 2. Architecture

## Three VM Setup

The system uses **three separate FreeBSD virtual machines**.

```text
+----------------+        +----------------+        +----------------+
|   KDC VM       |        |   Client VM    |        |   Server VM    |
|----------------|        |----------------|        |----------------|
| Kerberos Realm |        | sfc-client     |        | sfc-server     |
| krb5kdc        |        | kinit alice    |        | keytab stored  |
| kadmind        |        | tamper_proxy   |        | receives file  |
+----------------+        +----------------+        +----------------+
```

---

# 3. Role of Each VM

## 3.1 KDC VM

Responsible for:

* Kerberos Realm management
* Principal database
* Ticket Granting Ticket (TGT) issuance
* Service ticket issuance

Daemons:

```text
krb5kdc
kadmind
```

---

## 3.2 Client VM

Responsible for:

* User login
* Obtaining Kerberos credentials using `kinit`
* Running secure sender program `sfc-client`
* Running tamper proxy during attack simulation

---

## 3.3 Server VM

Responsible for:

* Running `sfc-server`
* Accepting Kerberos-authenticated GSS context
* Receiving wrapped AES key
* Decrypting AES-GCM file
* Rejecting tampered transfers safely

---

# 4. Kerberos Realm Configuration

Realm used:

```text
EXAMPLE.COM
```

Example client `/etc/krb5.conf`

```ini
[libdefaults]
 default_realm = EXAMPLE.COM
 dns_lookup_kdc = false
 dns_lookup_realm = false

[realms]
 EXAMPLE.COM = {
     kdc = 192.168.1.20
     admin_server = 192.168.1.20
 }

[domain_realm]
 .local = EXAMPLE.COM
 local = EXAMPLE.COM
```

---

# 5. Principals Created

The following principals were created:

```text
alice@EXAMPLE.COM
root/admin@EXAMPLE.COM
krbtgt/EXAMPLE.COM@EXAMPLE.COM
sfc/server@EXAMPLE.COM
```

---

# 6. Service Principal Mapping

The service principal:

```text
sfc/server@EXAMPLE.COM
```

maps directly to the server application.

The client imports:

```c
char service[] = "sfc@server";
```

using:

```c
gss_import_name(..., GSS_C_NT_HOSTBASED_SERVICE, ...)
```

This resolves to:

```text
sfc/server@EXAMPLE.COM
```

The server possesses the matching secret key in its keytab.

---

# 7. Server Keytab

Generated on KDC and installed on server:

```sh
kadmin.local
addprinc -randkey sfc/server
ktadd sfc/server
```

Copied to server VM as:

```text
/etc/krb5.keytab
```

Used automatically by GSS-API acceptor side.

---

# 8. Kerberos Authentication Flow

## Step 1 – User obtains TGT

Client runs:

```sh
kinit alice@EXAMPLE.COM
```

KDC returns:

```text
krbtgt/EXAMPLE.COM@EXAMPLE.COM
```

---

## Step 2 – Client requests service ticket

When `sfc-client` starts, it requests ticket for:

```text
sfc/server@EXAMPLE.COM
```

KDC returns service ticket.

---

## Step 3 – GSS Context Establishment

Client:

```c
gss_init_sec_context()
```

Server:

```c
gss_accept_sec_context()
```

Tokens exchanged over TCP until:

```text
Authenticated context established.
```

This proves:

* Client authenticated as `alice`
* Server authenticated as service principal
* Mutual trust established

---

# 9. Binding K_file to Kerberos Context

After successful GSS context creation, the client generates:

```text
K_file = random 256-bit AES key
```

Then securely sends it using:

```c
gss_wrap()
```

This means:

* Only a successfully authenticated server can unwrap it.
* K_file is not pre-shared.
* K_file depends on successful Kerberos-authenticated session.

Therefore file encryption is cryptographically bound to Kerberos authentication.

---

# 10. Why This Design Is Secure

Without successful Kerberos authentication:

* No GSS context
* No wrapped AES key acceptance
* No file decryption possible

Thus attackers cannot inject their own key or bypass authentication.

---

# 11. File Protection using AES-256-GCM

The file contents are encrypted using:

```text
AES-256-GCM
```

Outputs:

* Nonce (12 bytes)
* Ciphertext
* Authentication Tag (16 bytes)

Sent as:

```text
[length][nonce][ciphertext][tag]
```

---

# 12. Nonce Discipline

Each transfer uses:

```c
RAND_bytes(nonce, NONCE_LEN);
```

Fresh random nonce per encryption.

Nonce reuse under same key is avoided.

---

# 13. Receiver Verification Safety

Server must verify GCM tag **before writing plaintext**.

If verification fails:

```text
Tag verify failed.
Transfer rejected.
```

No file written.

This prevents:

* partial plaintext leakage
* corrupted output
* unsafe recovery

---

# 14. Compilation

## Required Packages

```sh
pkg install krb5 openssl gmake
```

## Build

```sh
make clean
make
```

Builds:

```text
sfc-client
sfc-server
tamper_proxy
```

---

# 15. Execution Sequence

---

## 15.1 Start KDC VM

```sh
sudo /usr/local/sbin/krb5kdc
sudo /usr/local/sbin/kadmind
```

---

## 15.2 On Client VM – Authenticate

```sh
kinit alice@EXAMPLE.COM
klist
```

Expected:

```text
Default principal: alice@EXAMPLE.COM
```

---

## 15.3 On Server VM – Start Receiver

```sh
./sfc-server
```

Expected:

```text
Server listening on 5555
```

---

## 15.4 On Client VM – Normal Transfer

```sh
./sfc-client test.txt
```

Expected:

Client:

```text
Connected.
Authenticated context established.
Generated AES key...
Wrapped AES key sent.
Encrypted file sent.
```

Server:

```text
Authenticated context established.
Received AES key...
File received safely.
```

---

# 16. Tampering Workflow using Relay

A tamper proxy is inserted between client and server.

```text
Client ---> Tamper Proxy ---> Server
```

Proxy listens on:

```text
6666
```

and forwards to real server:

```text
192.168.1.30:5555
```

---

## Run Proxy

```sh
./tamper_proxy
```

Expected:

```text
Tamper proxy listening on 6666
```

---

## Run Client Through Proxy

Client connects to proxy port.

---

# 17. Proxy Logic

Proxy forwards traffic but flips one byte in ciphertext:

```c
buf[n - 30] ^= 0xFF;
```

This simulates in-transit adversarial modification.

---

# 18. Expected Tampered Behavior

Client:

```text
Encrypted file sent.
```

Proxy:

```text
Ciphertext tampered.
```

Server:

```text
Authenticated context established.
Received AES key...
Tag verification failed.
Transfer rejected.
```

No output file created.

---

# 19. Why Tampering Fails

AES-GCM authenticates ciphertext.

Any change to:

* nonce
* ciphertext
* tag

causes authentication failure.

This demonstrates integrity protection.

---

# 20. Security Separation of Components

The design clearly separates:

## Authentication

Kerberos + GSS-API

## Key Establishment

Wrapped AES session key

## File Protection

AES-GCM

## Transport

TCP socket channel

This avoids an unstructured monolithic design.

---

# 21. Important Observations

TCP is stream-based, not packet-based.

Therefore tamper proxy should not rely on packet numbers like:

```c
packet_count >= 4
```

Instead it should tamper based on content size or location.

---

# 22. References Used

System manuals consulted as required:

```text
man 3 gssapi
man 3 gss_init_sec_context
man 3 gss_accept_sec_context
man 3 gss_acquire_cred
man -k EVP
man -k GCM
```

MIT Kerberos documentation consulted for:

* principals
* keytabs
* realm setup
* KDC administration
* GSS-API usage

Assignment requirements referenced from provided brief 

---

# 23. Final Result

This implementation successfully demonstrates:

✅ Real Kerberos authentication
✅ Correct service ticketing
✅ Mutual GSS context establishment
✅ Secure file-key transfer
✅ AES-GCM confidentiality and integrity
✅ Tampering detection
✅ Safe rejection behavior

---

# 24. Reproducibility Summary

```sh
# Client
kinit alice@EXAMPLE.COM
./sfc-client test.txt

# Server
./sfc-server

# Tamper Test
./tamper_proxy
./sfc-client test.txt
```

---

# End of README
