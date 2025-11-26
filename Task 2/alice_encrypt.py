# alice_encrypt.py
import os
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend


def load_bob_public_key(path: str = "public.pem"):
    """
    Load Bob's RSA public key from PEM file.
    """
    with open(path, "rb") as f:
        public_pem = f.read()
    public_key = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )
    return public_key


def aes_encrypt_file(plaintext: bytes):
    """
    Encrypt plaintext using AES-256 in CBC mode with PKCS7 padding.
    Returns: (aes_key, iv, ciphertext)
    """
    # 32-byte key = 256-bit AES
    aes_key = os.urandom(32)
    # 16-byte IV for AES-CBC
    iv = os.urandom(16)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return aes_key, iv, ciphertext


def rsa_encrypt_aes_key(aes_key: bytes, public_key):
    """
    Encrypt AES key with Bob's RSA public key using OAEP + SHA-256.
    """
    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def compute_sha256(data: bytes) -> str:
    """
    Compute SHA-256 hash of given data and return hex string.
    """
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def main():
    # 1. Read Alice's plaintext message file
    with open("alice_message.txt", "rb") as f:
        plaintext = f.read()

    # (Optional but useful) Compute and print hash of original file
    original_hash = compute_sha256(plaintext)
    print(f"Original alice_message.txt SHA-256: {original_hash}")

    # 2. Load Bob's public key
    public_key = load_bob_public_key("public.pem")

    # 3. Encrypt file with AES-256
    aes_key, iv, ciphertext = aes_encrypt_file(plaintext)

    # 4. Encrypt AES key with Bob's RSA public key
    encrypted_aes_key = rsa_encrypt_aes_key(aes_key, public_key)

    # 5. Write encrypted payloads to disk

    # AES-encrypted file: store IV + ciphertext in one binary
    with open("encrypted_file.bin", "wb") as f:
        f.write(iv + ciphertext)

    # RSA-encrypted AES key
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key)

    print("Encryption complete:")
    print("- encrypted_file.bin written (IV + AES ciphertext)")
    print("- aes_key_encrypted.bin written (RSA-encrypted AES key)")


if __name__ == "__main__":
    main()
