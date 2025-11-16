#!/usr/bin/env python3
import argparse, os, datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--ca-key", default="certs/ca.key.pem")
    parser.add_argument("--ca-cert", default="certs/ca.crt.pem")
    args = parser.parse_args()

    outdir = os.path.dirname(args.out)
    ensure_dir(outdir)
    key_path = args.out + ".key.pem"
    cert_path = args.out + ".crt.pem"

    # Load CA
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    with open(args.ca_key, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(args.ca_cert, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Generate key for server/client
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    # Create certificate signed by CA
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365*3))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Key:", key_path)
    print("Cert:", cert_path)

if __name__ == "__main__":
    main()
