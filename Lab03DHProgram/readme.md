# 🔐 Diffie-Hellman Secure Communication & MITM Simulation

## 📌 Overview
This project demonstrates:

* ✅ Diffie-Hellman Key Exchange
* ✅ Secure session establishment using a stateful PRNG
* ✅ XOR-based stream cipher encryption
* ❌ Man-In-The-Middle (MITM) attack simulation
* 🔎 Active message interception and modification

The program simulates two scenarios:

1. **Benign Secure Communication**
2. **Malicious MITM Attack**

---

## 🧠 Concepts Demonstrated

### 1️⃣ Diffie-Hellman Key Exchange

* Uses large prime `P`
* Generator `G = 2`
* Alice and Bob generate private keys
* Public keys exchanged over network
* Shared secret computed as:

```
S = (g^b)^a mod P = (g^a)^b mod P
```

---

### 2️⃣ Secure Stateful PRNG

* Seeded using shared secret
* Uses SHA-256
* Provides:

  * Forward secrecy
  * Rollback resistance
* Generates keystream for XOR encryption

---

### 3️⃣ XOR Stream Cipher

Encryption:

```
Ciphertext = Plaintext ⊕ Keystream
```

Decryption:

```
Plaintext = Ciphertext ⊕ Keystream
```

---

### 4️⃣ MITM Attack Simulation (Mallory)

Mallory:

* Intercepts public keys
* Replaces them with her own
* Establishes two separate secrets:

  * Alice ↔ Mallory
  * Bob ↔ Mallory
* Decrypts, modifies, and re-encrypts messages

Demonstrates how **unauthenticated Diffie-Hellman is vulnerable**.

---

# 🖥️ Program Flow

## ✅ SCENARIO A – Secure Communication

1. Alice & Bob generate key pairs
2. Exchange public keys
3. Compute identical shared secret
4. Encrypt and send message
5. Bob successfully decrypts
6. Integrity verified

---

## ❌ SCENARIO B – MITM Attack

1. Mallory activates on network
2. Intercepts public keys
3. Sends her own public key instead
4. Creates separate shared secrets
5. Intercepts encrypted message
6. Decrypts and modifies payload
7. Re-encrypts for Bob
8. Bob receives modified message

---

# 🔒 Security Lessons

### ✔ Secure Version

* Alice and Bob share identical secret
* Message integrity preserved

### ❌ Vulnerable Version

* No authentication
* Mallory successfully intercepts
* Alice and Bob compute different secrets
* Message modified without detection

---

# ⚠ Why This Attack Works

Diffie-Hellman provides:

* ✔ Confidentiality
* ❌ No Authentication

Without digital signatures or certificates, attackers can impersonate parties.

---

# 🛡 How To Fix This

To prevent MITM:

* Use authenticated Diffie-Hellman
* Add:

  * Digital Signatures (RSA/ECDSA)
  * Certificates (PKI)
  * Pre-shared public keys
