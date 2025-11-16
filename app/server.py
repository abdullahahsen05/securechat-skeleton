import socket, threading, os, json, base64, hashlib, datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympad
from cryptography import x509
from app.storage import db
from datetime import datetime, timezone 
import secrets

HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", 9000))
TRANSCRIPT_DIR = "transcripts"
os.makedirs(TRANSCRIPT_DIR, exist_ok=True)

# Load server key/cert
with open("certs/server.key.pem", "rb") as f:
    SERVER_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open("certs/server.crt.pem", "rb") as f:
    SERVER_CERT = x509.load_pem_x509_certificate(f.read())
with open("certs/ca.crt.pem", "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())

def verify_cert(cert_pem):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        CA_CERT.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asympad.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return cert
    except:
        return None

def aes_encrypt(key, plaintext):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv + ct

def aes_decrypt(key, data):
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def dh_shared_key(a_priv, b_pub, p):
    Ks = pow(b_pub, a_priv, p)
    return hashlib.sha256(Ks.to_bytes((Ks.bit_length()+7)//8, 'big')).digest()[:16]

clients = []

def handle_client(conn, addr):
    transcript = []
    seqno = 0
    client_hello = json.loads(conn.recv(8192).decode())
    client_cert = verify_cert(client_hello["client_cert"])
    if not client_cert:
        conn.send(b"BAD CERT")
        conn.close()
        return
    conn.send(json.dumps({"type":"server_hello","server_cert":SERVER_CERT.public_bytes(serialization.Encoding.PEM).decode(),"nonce":base64.b64encode(secrets.token_bytes(16)).decode()}).encode())

    dh_client = json.loads(conn.recv(8192).decode())
    g, p, A = dh_client["g"], dh_client["p"], dh_client["A"]
    b = secrets.randbelow(p-2)+1
    B = pow(g, b, p)
    conn.send(json.dumps({"type":"dh_server","B":B}).encode())
    session_key = dh_shared_key(b, A, p)

    enc_msg = base64.b64decode(conn.recv(8192))
    creds = json.loads(aes_decrypt(session_key, enc_msg).decode())
    username = creds["username"]
    pwd_hash = base64.b64decode(creds["pwd"]).hex()

    if not db.verify_user(username, pwd_hash):
        db.create_user(username, pwd_hash)

    conn.send(b"Login/Registration successful! Start chatting...\n")
    clients.append((conn, username, client_cert, session_key))

    while True:
        try:
            enc_msg = conn.recv(8192)
            if not enc_msg: break
            decrypted = json.loads(aes_decrypt(session_key, base64.b64decode(enc_msg)).decode())
            if decrypted["seqno"] <= seqno: continue
            seqno = decrypted["seqno"]
            transcript.append(decrypted)
            print(f"[{username}] {decrypted['ct']}")
        except:
            break

    transcript_bytes = json.dumps(transcript).encode()
    receipt_hash = hashlib.sha256(transcript_bytes).digest()
    receipt_sig = SERVER_KEY.sign(receipt_hash, asympad.PKCS1v15(), hashes.SHA256())
    receipt = {"type":"receipt","peer":"server","first_seq":transcript[0]["seqno"] if transcript else 0,"last_seq":seqno,"transcript_sha256":receipt_hash.hex(),"sig":base64.b64encode(receipt_sig).decode()}
    with open(f"{TRANSCRIPT_DIR}/{username}_receipt.json","w") as f:
        json.dump(receipt,f,indent=2)
    conn.close()

def main():
    db.init_db()
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((HOST,PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client,args=(conn,addr)).start()

if __name__ == "__main__":
    main()
