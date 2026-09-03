# aes256_audio_encrypt_decrypt.py
# Encrypts / decrypts any audio file (mp3, wav, etc.) using AES-256-CBC + password

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,              # 256 bits
        salt=salt,
        iterations=200_000,     # high enough to resist brute-force
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_audio(input_path: str, output_path: str = None):
    if output_path is None:
        output_path = input_path + ".aes256"

    password = getpass.getpass("Enter password to encrypt: ")
    if not password:
        print("Password cannot be empty!")
        return

    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)

    key = derive_key(password, salt)

    # Read audio file (binary)
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Pad to multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save: salt (16) + iv (16) + ciphertext
    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print(f"Encrypted audio saved → {output_path}")
    print("Keep your password safe — you will need the exact same one to decrypt.")


def decrypt_audio(input_path: str, output_path: str = None):
    if output_path is None:
        # Remove .aes256 extension or add .decrypted
        if input_path.endswith(".aes256"):
            output_path = input_path[:-7]   # remove .aes256
        else:
            output_path = input_path + ".decrypted"

    password = getpass.getpass("Enter password to decrypt: ")
    if not password:
        print("Password cannot be empty!")
        return

    # Read encrypted file
    with open(input_path, 'rb') as f:
        raw = f.read()

    if len(raw) < 32:
        print("File too small — probably not encrypted with this method.")
        return

    salt = raw[:16]
    iv = raw[16:32]
    ciphertext = raw[32:]

    key = derive_key(password, salt)

    # Decrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    try:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        print("Decryption failed — wrong password or file corrupted / not encrypted properly.")
        return

    # Save decrypted audio
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted audio saved → {output_path}")
    print("You can now play it with any media player.")


if __name__ == "__main__":
    print("AES-256 Audio File Encrypt/Decrypt Tool")
    print("----------------------------------------")
    mode = input("Enter 'e' to encrypt, 'd' to decrypt: ").strip().lower()

    if mode == 'e':
        path = input("Enter path to audio file (mp3/wav/etc): ").strip()
        if not os.path.isfile(path):
            print("File not found!")
        else:
            encrypt_audio(path)

    elif mode == 'd':
        path = input("Enter path to encrypted file (.aes256): ").strip()
        if not os.path.isfile(path):
            print("File not found!")
        else:
            decrypt_audio(path)

    else:
        print("Invalid choice. Use 'e' or 'd'.")