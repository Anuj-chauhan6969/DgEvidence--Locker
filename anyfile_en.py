# hybrid_aes256_chacha_large_file_manual.py
# Supports very large files (>2GB) - chunked encryption/decryption
# AES-256-CBC protects ChaCha20-Poly1305 session key + nonce
# ChaCha20-Poly1305 encrypts file content in chunks

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
import os
import getpass

def derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_file():
    print("\n" + "="*60)
    print("  ENCRYPT FILE  (AES-256 + ChaCha20-Poly1305 hybrid - LARGE FILES OK)")
    print("="*60 + "\n")

    while True:
        path = input("Full path to file to encrypt:\n> ").strip()
        if os.path.isfile(path):
            break
        print("→ File not found. Please check the path and try again.\n")

    password = getpass.getpass("Enter password: ")
    if len(password) < 10:
        print("→ Warning: short password — better security with 12+ characters\n")

    # Prepare ChaCha20 session key and initial nonce
    chacha_key   = os.urandom(32)
    base_nonce   = os.urandom(8)          # 64-bit fixed part
    nonce_counter = 0                      # will increment per chunk

    # Protect ChaCha key + base_nonce with AES-256-CBC
    salt     = os.urandom(32)
    aes_iv   = os.urandom(16)
    master_key = derive_master_key(password, salt)

    to_protect = chacha_key + base_nonce          # 32 + 8 = 40 bytes
    padder = padding.PKCS7(128).padder()
    padded = padder.update(to_protect) + padder.finalize()

    cipher = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv))
    encryptor = cipher.encryptor()
    encrypted_metadata = encryptor.update(padded) + encryptor.finalize()  # 48 bytes

    # Prepare output file
    out_path = path + ".hybrid.enc"
    CHUNK_SIZE = 512 * 1024 * 1024  # 512 MB - change if you want smaller/larger

    try:
        chacha = ChaCha20Poly1305(chacha_key)

        with open(path, "rb") as f_in:
            with open(out_path, "wb") as f_out:
                # Write header once
                f_out.write(salt + aes_iv + encrypted_metadata)

                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # Create nonce for this chunk: base + counter (big-endian)
                    nonce = base_nonce + nonce_counter.to_bytes(4, "big")
                    encrypted_chunk = chacha.encrypt(nonce, chunk, None)
                    f_out.write(encrypted_chunk)

                    nonce_counter += 1

        print("\nEncryption completed successfully")
        print(f"Output saved to: {out_path}")
        print(f"Original size: {os.path.getsize(path):,} bytes")
        print(f"Encrypted size: {os.path.getsize(out_path):,} bytes")

    except Exception as e:
        print("\nEncryption failed:", str(e))
        if os.path.exists(out_path):
            try:
                os.remove(out_path)
            except:
                pass
        return


def decrypt_file():
    print("\n" + "="*60)
    print("  DECRYPT FILE  (AES-256 + ChaCha20-Poly1305 hybrid - LARGE FILES OK)")
    print("="*60 + "\n")

    while True:
        path = input("Full path to encrypted file (.hybrid.enc):\n> ").strip()
        if os.path.isfile(path):
            break
        print("→ File not found. Please check the path.\n")

    password = getpass.getpass("Enter password: ")

    try:
        with open(path, "rb") as f:
            raw_header = f.read(32 + 16 + 48)  # salt + aes_iv + metadata
            if len(raw_header) != 96:
                print("File header is incomplete or corrupted.")
                return

        salt              = raw_header[0:32]
        aes_iv            = raw_header[32:48]
        encrypted_metadata = raw_header[48:96]

        master_key = derive_master_key(password, salt)

        # Decrypt metadata (ChaCha key + base_nonce)
        cipher = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted_metadata) + decryptor.finalize()

        try:
            unpadder = padding.PKCS7(128).unpadder()
            metadata = unpadder.update(padded) + unpadder.finalize()
        except ValueError:
            print("\n××× Wrong password or corrupted header ×××")
            return

        chacha_key = metadata[0:32]
        base_nonce = metadata[32:40]

        # Prepare output file
        out_path = path
        if out_path.endswith(".hybrid.enc"):
            out_path = out_path[:-11]
        else:
            out_path += ".decrypted"

        CHUNK_SIZE = 512 * 1024 * 1024  # same as encryption
        nonce_counter = 0

        try:
            chacha = ChaCha20Poly1305(chacha_key)

            with open(path, "rb") as f_in:
                f_in.seek(96)  # skip header

                with open(out_path, "wb") as f_out:
                    while True:
                        chunk = f_in.read(CHUNK_SIZE + 16)  # + tag size
                        if not chunk:
                            break

                        nonce = base_nonce + nonce_counter.to_bytes(4, "big")
                        try:
                            decrypted_chunk = chacha.decrypt(nonce, chunk, None)
                            f_out.write(decrypted_chunk)
                        except InvalidTag:
                            print("\n××× Authentication failed on chunk ×××")
                            print("Wrong password or file was tampered with")
                            if os.path.exists(out_path):
                                os.remove(out_path)
                            return

                        nonce_counter += 1

            print("\nDecryption completed successfully")
            print(f"Output saved to: {out_path}")

        except Exception as e:
            print("\nDecryption failed:", str(e))
            if os.path.exists(out_path):
                try:
                    os.remove(out_path)
                except:
                    pass

    except Exception as e:
        print("General error:", str(e))


if __name__ == "__main__":
    print("Hybrid AES-256 + ChaCha20-Poly1305 File Encryption/Decryption Tool")
    print("Supports very large files (chunked processing)\n")

    while True:
        print("\nChoose:")
        print("  1   →  Encrypt a file")
        print("  2   →  Decrypt a file")
        print("  q   →  Quit")

        choice = input("> ").strip().lower()

        if choice in ('1', 'e', 'encrypt'):
            encrypt_file()
        elif choice in ('2', 'd', 'decrypt'):
            decrypt_file()
        elif choice in ('q', 'quit', 'exit'):
            print("\nGoodbye!\n")
            break
        else:
            print("Please enter 1, 2 or q")