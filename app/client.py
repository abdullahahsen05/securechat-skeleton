import socket, os, json, base64, hashlib
from cryptography.hazmat.primitives import serialization, hashes, padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography import x509
import secrets, datetime, sys
from datetime import datetime, timezone

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", 9000))

# Load client key/cert
try:
    with open("certs/client.key.pem", "rb") as f:
        CLIENT_KEY = serialization.load_pem_private_key(f.read(), password=None)
    with open("certs/client.crt.pem", "rb") as f:
        CLIENT_CERT = x509.load_pem_x509_certificate(f.read())
except Exception as e:
    print("[ERROR] Loading client cert/key failed:", e)
    sys.exit(1)

# Load CA
try:
    with open("certs/ca.crt.pem", "rb") as f:
        CA_CERT = x509.load_pem_x509_certificate(f.read())
except Exception as e:
    print("[ERROR] Loading CA cert failed:", e)
    sys.exit(1)

def verify_cert(cert_pem):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        CA_CERT.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asympadding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("[*] Certificate verification passed")
        return cert
    except Exception as e:
        print("[ERROR] BAD CERT:", e)
        return None

def aes_encrypt(key, plaintext):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    iv = secrets.token_bytes(16)
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

def main():
    print("[*] Starting client...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print(f"[*] Connected to server at {HOST}:{PORT}")
    except Exception as e:
        print("[ERROR] Connection failed:", e)
        return

    # Step 1: Control Plane
    try:
        hello = json.dumps({
            "type": "hello",
            "client_cert": CLIENT_CERT.public_bytes(serialization.Encoding.PEM).decode(),
            "nonce": base64.b64encode(secrets.token_bytes(16)).decode()
        }).encode()
        s.send(hello)
        print("[*] Sent hello with client certificate")

        server_hello = json.loads(s.recv(8192).decode())
        server_cert_pem = server_hello.get("server_cert")
        server_cert = verify_cert(server_cert_pem)
        if not server_cert:
            print("[ERROR] Server certificate invalid")
            s.close()
            return
    except Exception as e:
        print("[ERROR] Control plane failed:", e)
        s.close()
        return

    # Step 2: Diffie-Hellman
    try:
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
        g = 2
        a = secrets.randbelow(p-2) + 1
        A = pow(g, a, p)
        dh_client = json.dumps({"type":"dh_client","g":g,"p":p,"A":A}).encode()
        s.send(dh_client)
        print("[*] Sent DH client parameters")

        dh_server = json.loads(s.recv(8192).decode())
        B = dh_server["B"]
        session_key = dh_shared_key(a, B, p)
        print("[*] Derived session key")
    except Exception as e:
        print("[ERROR] DH key exchange failed:", e)
        s.close()
        return

    # Step 3: Encrypt login credentials
    try:
        print("[*] Ready for login/registration")
        username = input("Username: ")
        password = input("Password: ")
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).digest()
        creds = {
            "username": username,
            "pwd": base64.b64encode(pwd_hash).decode(),
            "salt": base64.b64encode(salt).decode()
        }
        s.send(base64.b64encode(aes_encrypt(session_key, json.dumps(creds).encode())))
        print("[*] Credentials sent, login/registration done!")
    except Exception as e:
        print("[ERROR] Sending credentials failed:", e)
        s.close()
        return

    # Step 4: Chat loop
    seqno = 0
    while True:
        try:
            msg = input()
            ts = int(datetime.now(timezone.utc).timestamp() * 1000)
            seqno += 1
            ct = base64.b64encode(aes_encrypt(session_key, msg.encode())).decode()
            sig = base64.b64encode(
                CLIENT_KEY.sign(
                    hashlib.sha256(f"{seqno}{ts}{ct}".encode()).digest(),
                    asympadding.PKCS1v15(),
                    hashes.SHA256()
                )
            ).decode()
            msg_json = json.dumps({"type":"msg","seqno":seqno,"ts":ts,"ct":ct,"sig":sig})
            s.send(base64.b64encode(aes_encrypt(session_key, msg_json.encode())))
        except Exception as e:
            print("[ERROR] Chat error:", e)
            break

if __name__ == "__main__":
    main()
"# Client skeleton" 
"print('[*] Certificate verification step loaded')" 
"print('[*] Diffie-Hellman key exchange implemented')" 
"# AES encryption/decryption functions added" 
