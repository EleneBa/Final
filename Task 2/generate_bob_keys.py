# generate_bob_keys.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair():
    # Generate Bob's RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate corresponding public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Persist to disk with names required by the task
    with open("private.pem", "wb") as f:
        f.write(private_pem)

    with open("public.pem", "wb") as f:
        f.write(public_pem)

    print("Bob's RSA key pair generated: private.pem, public.pem")


if __name__ == "__main__":
    generate_rsa_keypair()
