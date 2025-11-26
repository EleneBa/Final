# encrypt_message.py
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend


def load_rsa_public_key(path: str = "rsa_public.pem"):
    """
    Load User A's RSA public key from a PEM file.
    """
    with open(path, "rb") as f:
        public_pem = f.read()
    public_key = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )
    return public_key


def aes_encrypt_message(plaintext: bytes):
    """
    Encrypt the plaintext using AES-256 in CBC mode with PKCS7 padding.

    Returns:
        aes_key (bytes): 32-byte AES key.
        iv (bytes): 16-byte initialization vector.
        ciphertext (bytes): Encrypted data.
    """
    # 32 bytes = 256 bits for AES-256
    aes_key = os.urandom(32)

    # 16-byte IV for AES CBC
    iv = os.urandom(16)

    # PKCS7 padding to align with AES block size (128 bits)
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
    Encrypt the AES key using RSA (public key) and OAEP padding.
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


def main():
    # 1. Read plaintext message from message.txt
    with open("message.txt", "rb") as f:
        plaintext = f.read()

    # 2. Load User A's public RSA key
    public_key = load_rsa_public_key("rsa_public.pem")

    # 3. Encrypt the message with AES-256
    aes_key, iv, ciphertext = aes_encrypt_message(plaintext)

    # 4. Encrypt the AES key with RSA
    encrypted_aes_key = rsa_encrypt_aes_key(aes_key, public_key)

    # 5. Persist outputs required by the assignment

    # Store IV + ciphertext together in one file
    with open("encrypted_message.bin", "wb") as f:
        f.write(iv + ciphertext)

    # Store RSA-encrypted AES key
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key)

    print("Encryption complete:")
    print("- encrypted_message.bin created (IV + ciphertext)")
    print("- aes_key_encrypted.bin created (RSA-encrypted AES key)")


if __name__ == "__main__":
    main()
