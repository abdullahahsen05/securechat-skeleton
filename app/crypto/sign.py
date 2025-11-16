from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

private_key = RSA.generate(2048)
public_key = private_key.publickey()

def sign(data: bytes, key=None) -> bytes:
    key = key or private_key
    h = SHA256.new(data)
    return pkcs1_15.new(key).sign(h)

def verify(sig: str, seqno: int, ts: int, ct: str, pubkey) -> bool:
    data = f"{seqno}{ts}{ct}".encode()
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pubkey).verify(h, base64.b64decode(sig))
        return True
    except (ValueError, TypeError):
        return False

def get_private_key():
    return private_key

def get_public_key(username=None):
    return public_key
