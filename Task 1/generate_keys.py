# generate_keys.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair():
    # Generate private key (User A)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize private key to PEM (keep this secret)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # no password for this assignment
    )

    # Get public key (to share with User B)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write to disk
    with open("rsa_private.pem", "wb") as f:
        f.write(private_pem)

    with open("rsa_public.pem", "wb") as f:
        f.write(public_pem)

    print("RSA key pair generated: rsa_private.pem, rsa_public.pem")

if __name__ == "__main__":
    generate_rsa_keypair()
