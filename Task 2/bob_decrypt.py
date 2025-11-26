# bob_decrypt.py
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend


def load_bob_private_key(path: str = "private.pem"):
    """
    Load Bob's RSA private key from PEM file.
    """
    with open(path, "rb") as f:
        private_pem = f.read()
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )
    return private_key


def rsa_decrypt_aes_key(encrypted_key: bytes, private_key):
    """
    Decrypt AES key using Bob's RSA private key.
    """
    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def aes_decrypt_ciphertext(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt AES-256-CBC ciphertext and remove PKCS7 padding.
    """
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def compute_sha256_file(path: str) -> str:
    """
    Compute SHA-256 hash of a file by reading it in chunks.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    # 1. Load Bob's private key
    private_key = load_bob_private_key("private.pem")

    # 2. Read RSA-encrypted AES key
    with open("aes_key_encrypted.bin", "rb") as f:
        encrypted_aes_key = f.read()

    # 3. Decrypt AES key using RSA
    aes_key = rsa_decrypt_aes_key(encrypted_aes_key, private_key)

    # 4. Read encrypted file (IV + ciphertext)
    with open("encrypted_file.bin", "rb") as f:
        data = f.read()

    # First 16 bytes are IV, the rest is ciphertext
    iv = data[:16]
    ciphertext = data[16:]

    # 5. Decrypt file using AES key + IV
    plaintext = aes_decrypt_ciphertext(aes_key, iv, ciphertext)

    # 6. Write recovered message
    with open("decrypted_message.txt", "wb") as f:
        f.write(plaintext)

    print("Decryption complete: decrypted_message.txt written")

    # 7. Integrity verification with SHA-256
    original_hash = compute_sha256_file("alice_message.txt")
    decrypted_hash = compute_sha256_file("decrypted_message.txt")

    print(f"Original alice_message.txt SHA-256:  {original_hash}")
    print(f"Decrypted_message.txt SHA-256:       {decrypted_hash}")

    if original_hash == decrypted_hash:
        print("Integrity check: SUCCESS (hashes match)")
    else:
        print("Integrity check: FAILURE (hashes do not match)")


if __name__ == "__main__":
    main()
