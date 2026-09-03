# hybrid_chacha_aes_text_encrypt_decrypt.py
# Requirements: pip install cryptography

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=180000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_text():
    print("\n=== TEXT ENCRYPTION (ChaCha20-Poly1305 + AES-256 key protection) ===\n")
    
    plaintext = input("Enter or paste text to encrypt:\n").encode('utf-8')
    if not plaintext:
        print("No text entered. Exiting.")
        return

    password = getpass.getpass("Enter encryption password: ")
    if not password:
        print("Password cannot be empty.")
        return

    # ─── Prepare ChaCha20 ────────────────────────────────
    chacha_key = os.urandom(32)
    chacha_nonce = os.urandom(12)          # 96-bit nonce (standard for ChaCha20-Poly1305)
    
    # Encrypt message with ChaCha20-Poly1305 (authenticated)
    chacha = ChaCha20Poly1305(chacha_key)
    ciphertext = chacha.encrypt(chacha_nonce, plaintext, None)   # no associated data

    # ─── Protect ChaCha key + nonce with AES-256-CBC ─────
    salt = os.urandom(16)
    master_key = derive_key(password, salt)
    aes_iv = os.urandom(16)

    to_protect = chacha_key + chacha_nonce                      # 32 + 12 = 44 bytes
    padder = padding.PKCS7(128).padder()
    padded = padder.update(to_protect) + padder.finalize()

    cipher_aes = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv), backend=default_backend())
    encryptor = cipher_aes.encryptor()
    protected_metadata = encryptor.update(padded) + encryptor.finalize()

    # ─── Combine everything ──────────────────────────────
    final_data = (
        salt +               # 16 bytes
        aes_iv +             # 16 bytes
        protected_metadata + # 48 bytes (padded 44 → 48)
        ciphertext
    )

    # Base64 for easy copy-paste / sharing
    encoded = base64.b64encode(final_data).decode('ascii')

    print("\nEncrypted output (copy this):\n")
    print(encoded)
    print(f"\nLength: {len(encoded)} characters")


def decrypt_text():
    print("\n=== TEXT DECRYPTION ===\n")
    
    encoded = input("Paste the encrypted base64 string:\n").strip()
    if not encoded:
        print("No data entered.")
        return

    try:
        final_data = base64.b64decode(encoded)
    except Exception as e:
        print("Invalid base64 string.", e)
        return

    if len(final_data) < 16+16+48:
        print("Data too short — invalid format.")
        return

    password = getpass.getpass("Enter decryption password: ")

    # Parse
    pos = 0
    salt          = final_data[pos:pos+16]; pos += 16
    aes_iv        = final_data[pos:pos+16]; pos += 16
    protected_md  = final_data[pos:pos+48]; pos += 48
    ciphertext    = final_data[pos:]

    master_key = derive_key(password, salt)

    # Decrypt metadata (ChaCha key + nonce) with AES
    cipher_aes = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv), backend=default_backend())
    decryptor = cipher_aes.decryptor()
    padded = decryptor.update(protected_md) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(128).unpadder()
        metadata = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        print("Decryption failed → wrong password or corrupted data.")
        return

    chacha_key   = metadata[:32]
    chacha_nonce = metadata[32:44]

    # Decrypt message with ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(chacha_key)
    try:
        plaintext_bytes = chacha.decrypt(chacha_nonce, ciphertext, None)
        plaintext = plaintext_bytes.decode('utf-8')
        print("\nDecrypted text:\n")
        print(plaintext)
    except Exception as e:
        print("Authentication failed → wrong password, corrupted data, or tampered ciphertext.")
        print(e)


if __name__ == "__main__":
    print("ChaCha20 + AES-256 Hybrid Text Encrypt/Decrypt")
    print("---------------------------------------------\n")
    
    while True:
        choice = input("Choose:  [e]ncrypt   [d]ecrypt   [q]uit  → ").strip().lower()
        
        if choice == 'e':
            encrypt_text()
        elif choice == 'd':
            decrypt_text()
        elif choice in ('q', 'quit', 'exit'):
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Try again.\n")