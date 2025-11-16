Secure Chat Skeleton
1. Project Overview

This project implements a secure client-server chat system using AES-128 encryption, RSA signatures, and Diffie-Hellman key exchange, with a custom Public Key Infrastructure (PKI) for authentication. It ensures Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR).

2. Setup Instructions

Clone your forked repository:

git clone https://github.com/<your-username>/securechat-skeleton.git
cd securechat-skeleton


Activate Python virtual environment:

.venv\Scripts\activate.bat   # Windows
# or
source .venv/bin/activate    # Linux/macOS


Install dependencies:

pip install -r requirements.txt


Generate certificates:

python scripts/gen_ca.py
python scripts/gen_cert.py


Start the server:

python -m app.server


Start the client:

python -m app.client

3. Usage

On first run, register a new user (username/password).

For returning users, login using the same credentials.

Start chatting securely; all messages are encrypted and signed.

4. Security Features
4.1 Control Plane

Mutual certificate exchange and validation (X.509, CA-signed).

Registration/login credentials are encrypted via AES using a temporary DH-derived key.

Passwords stored in MySQL as salted SHA-256 hashes.

4.2 Key Agreement

Diffie-Hellman key exchange to derive session AES key.

AES-128 session key ensures confidentiality of all messages.

4.3 Data Plane

Messages encrypted with AES-128 (PKCS#7 padding).

SHA-256 hash over seqno || timestamp || ciphertext.

RSA signature over the digest to ensure integrity and authenticity.

Sequence numbers + timestamps prevent replay attacks.

4.4 Non-Repudiation

Transcript logged per session: seqno | timestamp | ciphertext | signature | peer-cert-fingerprint.

SessionReceipt generated:

{
  "type": "receipt",
  "peer": "client|server",
  "first_seq": ...,
  "last_seq": ...,
  "transcript_sha256": "...",
  "sig": "base64(RSA SIGN(transcript_sha256))"
}


Offline verification confirms authenticity and integrity; any edit breaks verification.

5. Testing & Evidence
5.1 Wireshark

Captured traffic shows only encrypted payloads.

Display filter used: tcp.port == 9000

No plaintext usernames, passwords, or messages visible.

5.2 Invalid Certificate Test

Tested forged/self-signed/expired certificates.

Server logs: BAD CERT for all invalid cases.

5.3 Tampering Test

Sent a message and flipped a single bit in the ciphertext.

Server rejects the message due to signature verification failure (SIG FAIL).

5.4 Replay Test

Resent old seqno.

Server rejected message (REPLAY).

5.5 Non-Repudiation Verification

Transcript exported at end of session.

SHA-256 digest of each message recomputed.

RSA signature of each digest verified.

SessionReceipt verified by checking transcript hash signature.

Any modification in transcript invalidates receipt signature.

6. MySQL Schema
CREATE TABLE users (
    email VARCHAR(255),
    username VARCHAR(255) UNIQUE,
    salt VARBINARY(16),
    pwd_hash CHAR(64)
);

-- Sample record:
INSERT INTO users (email, username, salt, pwd_hash) VALUES
('test@example.com', 'testuser', UNHEX('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'), '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');

7. Repository & Commits

All work done on forked repository.

10 meaningful commits demonstrating progressive development:

Initial project setup and environment.

CA generation and certificate issuance.

Client/server certificate validation.

Registration/login with encrypted credentials.

Diffie-Hellman session key derivation.

AES-128 encrypted messaging.

SHA-256 + RSA signature integration.

Transcript logging.

SessionReceipt & offline verification.

README update and test documentation.