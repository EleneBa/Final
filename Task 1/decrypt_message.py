# decrypt_message.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend

def load_rsa_private_key(path="rsa_private.pem"):
    with open(path, "rb") as f:
        private_pem = f.read()
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )
    return private_key

def rsa_decrypt_aes_key(encrypted_key: bytes, private_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def aes_decrypt_message(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def main():
    # 1. Load User A's private RSA key
    private_key = load_rsa_private_key("rsa_private.pem")

    # 2. Read the RSA-encrypted AES key
    with open("aes_key_encrypted.bin", "rb") as f:
        encrypted_aes_key = f.read()

    # 3. Decrypt the AES key with RSA
    aes_key = rsa_decrypt_aes_key(encrypted_aes_key, private_key)

    # 4. Read the IV + ciphertext from encrypted_message.bin
    with open("encrypted_message.bin", "rb") as f:
        data = f.read()

    # We wrote iv + ciphertext in encrypt_message.py
    iv = data[:16]             # first 16 bytes = IV
    ciphertext = data[16:]     # rest = ciphertext

    # 5. Decrypt the message with AES
    plaintext = aes_decrypt_message(aes_key, iv, ciphertext)

    # 6. Save to decrypted_message.txt
    with open("decrypted_message.txt", "wb") as f:
        f.write(plaintext)

    print("Decryption complete: decrypted_message.txt created")

if __name__ == "__main__":
    main()
