#!/usr/bin/env python3
import argparse
import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, help="CA common name")
    parser.add_argument("--outdir", default="certs", help="Output directory")
    args = parser.parse_args()

    ensure_dir(args.outdir)

    key_path = os.path.join(args.outdir, "ca.key.pem")
    cert_path = os.path.join(args.outdir, "ca.crt.pem")

    # Generate CA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Generate self-signed CA certificate
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("CA key:", key_path)
    print("CA cert:", cert_path)

if __name__ == "__main__":
    main()
