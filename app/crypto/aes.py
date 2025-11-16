from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct

def decrypt(key: bytes, data: bytes) -> bytes:
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
