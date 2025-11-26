\# Secure File Exchange Using RSA + AES



\## 1. Overview



This project demonstrates a hybrid encryption protocol:

\- \*\*AES-256\*\* (symmetric) is used to encrypt the actual file content.

\- \*\*RSA\*\* (asymmetric) is used only to encrypt (wrap) the AES key.



Alice wants to send Bob a secret file. Bob owns an RSA key pair (`private.pem`, `public.pem`).



\## 2. Key Generation (Bob)



\- `generate\_bob\_keys.py` uses Python's `cryptography` library to create a 2048-bit RSA key pair.

\- The private key is saved as `private.pem` and kept secret.

\- The public key is saved as `public.pem` and is shared with Alice.



\## 3. Encryption Flow (Alice)



1\. Alice creates `alice\_message.txt` (plaintext).

2\. `alice\_encrypt.py`:

&nbsp;  - Reads `alice\_message.txt`.

&nbsp;  - Generates a random 32-byte AES-256 key and a 16-byte IV.

&nbsp;  - Encrypts the file using AES-256 in CBC mode with PKCS7 padding.

&nbsp;  - Concatenates `IV + ciphertext` and writes it to `encrypted\_file.bin`.

&nbsp;  - Loads Bob's `public.pem`.

&nbsp;  - Encrypts the AES key with RSA using OAEP + SHA-256.

&nbsp;  - Writes the RSA-encrypted AES key to `aes\_key\_encrypted.bin`.



\## 4. Decryption Flow (Bob)



1\. Bob runs `bob\_decrypt.py`:

&nbsp;  - Loads his RSA private key from `private.pem`.

&nbsp;  - Reads `aes\_key\_encrypted.bin` and decrypts it to recover the AES key.

&nbsp;  - Reads `encrypted\_file.bin`, splits it into:

&nbsp;    - IV (first 16 bytes)

&nbsp;    - Ciphertext (remaining bytes)

&nbsp;  - Decrypts the ciphertext with AES-256-CBC using the recovered AES key and IV.

&nbsp;  - Writes the plaintext to `decrypted\_message.txt`.

2\. The script computes SHA-256 hashes of:

&nbsp;  - `alice\_message.txt`

&nbsp;  - `decrypted\_message.txt`

3\. If the hashes match, the integrity check is successful (file was not modified).



\## 5. AES vs RSA (Speed, Use Case, Security)



\- \*\*AES\*\*

&nbsp; - Type: Symmetric key algorithm.

&nbsp; - Speed: Very fast, efficient for large files and streaming data.

&nbsp; - Use case: Bulk data encryption (files, network traffic, databases).

&nbsp; - Security: AES-256 is considered very secure when keys are managed properly.



\- \*\*RSA\*\*

&nbsp; - Type: Asymmetric key algorithm (public/private key).

&nbsp; - Speed: Much slower than AES, especially for large data.

&nbsp; - Use case: Key exchange, digital signatures, encrypting small pieces of data such as session keys.

&nbsp; - Security: Security depends on key size (e.g. 2048-bit) and correct padding (OAEP).



\- \*\*Hybrid approach\*\*

&nbsp; - Combines both:

&nbsp;   - Encrypt large data with AES (fast).

&nbsp;   - Encrypt the AES key with RSA (solves key distribution problem).

&nbsp; - This is the standard design in many real-world protocols (e.g. TLS).



