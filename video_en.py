# hybrid_aes256_chacha_video_large_manual.py
# Interactive encryption/decryption for large VIDEO files (chunked)
# AES-256-CBC protects ChaCha20-Poly1305 session key + base nonce
# Supports files >> 2 GB without OverflowError

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
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


def encrypt_video():
    print("\n" + "="*70)
    print("  ENCRYPT VIDEO FILE  (AES-256 + ChaCha20-Poly1305 hybrid – LARGE FILES)")
    print("="*70 + "\n")
    print("Supports .mp4, .mkv, .avi, .mov, etc. — even 10+ GB files\n")

    while True:
        path = input("Full path to video file to encrypt:\n> ").strip()
        if os.path.isfile(path):
            break
        print("→ File not found. Check path and try again.\n")

    password = getpass.getpass("Enter strong password: ")
    if len(password) < 12:
        print("→ Warning: short password — 12+ characters recommended for videos\n")

    # Session key & base nonce (fixed 8 bytes + 4-byte counter per chunk)
    chacha_key   = os.urandom(32)
    base_nonce   = os.urandom(8)              # 64-bit fixed part
    nonce_counter = 0

    # AES-256 protects key + base_nonce
    salt     = os.urandom(32)
    aes_iv   = os.urandom(16)
    master_key = derive_master_key(password, salt)

    to_protect = chacha_key + base_nonce          # 40 bytes
    padder = padding.PKCS7(128).padder()
    padded = padder.update(to_protect) + padder.finalize()

    cipher = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv))
    encryptor = cipher.encryptor()
    encrypted_metadata = encryptor.update(padded) + encryptor.finalize()  # 48 bytes

    out_path = path + ".hybridvid.enc"
    CHUNK_SIZE = 512 * 1024 * 1024           # 512 MB — reduce to 256*1024*1024 if needed

    try:
        chacha = ChaCha20Poly1305(chacha_key)

        with open(path, "rb") as f_in:
            with open(out_path, "wb") as f_out:
                # Header: salt + aes_iv + encrypted_metadata
                f_out.write(salt + aes_iv + encrypted_metadata)

                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    nonce = base_nonce + nonce_counter.to_bytes(4, byteorder="big")
                    enc_chunk = chacha.encrypt(nonce, chunk, None)
                    f_out.write(enc_chunk)

                    nonce_counter += 1

        orig_size = os.path.getsize(path)
        enc_size  = os.path.getsize(out_path)
        print("\nVideo encryption completed")
        print(f"Output: {out_path}")
        print(f"Original: {orig_size:,} bytes (~{orig_size / 1e9:.2f} GB)")
        print(f"Encrypted: {enc_size:,} bytes (~{enc_size / 1e9:.2f} GB)")
        print(f"Overhead: ~96 bytes + per-chunk tags")

    except Exception as e:
        print("\nEncryption failed:", str(e))
        if os.path.exists(out_path):
            try: os.remove(out_path)
            except: pass


def decrypt_video():
    print("\n" + "="*70)
    print("  DECRYPT VIDEO FILE  (AES-256 + ChaCha20-Poly1305 hybrid – LARGE FILES)")
    print("="*70 + "\n")

    while True:
        path = input("Full path to encrypted video (.hybridvid.enc):\n> ").strip()
        if os.path.isfile(path):
            break
        print("→ File not found. Check path.\n")

    password = getpass.getpass("Enter password: ")

    try:
        with open(path, "rb") as f:
            header = f.read(32 + 16 + 48)           # salt + iv + metadata
            if len(header) != 96:
                print("Incomplete/corrupted header.")
                return

        salt              = header[0:32]
        aes_iv            = header[32:48]
        encrypted_metadata = header[48:96]

        master_key = derive_master_key(password, salt)

        cipher = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted_metadata) + decryptor.finalize()

        try:
            unpadder = padding.PKCS7(128).unpadder()
            metadata = unpadder.update(padded) + unpadder.finalize()
        except ValueError:
            print("\nWrong password or corrupted header.")
            return

        chacha_key = metadata[0:32]
        base_nonce = metadata[32:40]

        out_path = path
        if out_path.endswith(".hybridvid.enc"):
            out_path = out_path[:-13]               # remove .hybridvid.enc
        else:
            out_path += ".decrypted"

        CHUNK_SIZE = 512 * 1024 * 1024
        nonce_counter = 0

        chacha = ChaCha20Poly1305(chacha_key)

        with open(path, "rb") as f_in:
            f_in.seek(96)  # skip header

            with open(out_path, "wb") as f_out:
                while True:
                    chunk = f_in.read(CHUNK_SIZE + 16)  # + Poly1305 tag
                    if not chunk:
                        break

                    nonce = base_nonce + nonce_counter.to_bytes(4, byteorder="big")

                    try:
                        dec_chunk = chacha.decrypt(nonce, chunk, None)
                        f_out.write(dec_chunk)
                    except InvalidTag:
                        print("\nAuthentication failed (wrong password or tampered file)")
                        if os.path.exists(out_path):
                            try: os.remove(out_path)
                            except: pass
                        return

                    nonce_counter += 1

        print("\nVideo decryption completed")
        print(f"Output saved to: {out_path}")

    except Exception as e:
        print("Error during decryption:", str(e))
        if os.path.exists(out_path):
            try: os.remove(out_path)
            except: pass


if __name__ == "__main__":
    print("Video File Encryption/Decryption Tool (Hybrid AES-256 + ChaCha20-Poly1305)")
    print("Supports large videos – chunked processing – no memory overflow\n")

    while True:
        print("\nChoose action:")
        print("  1   →  Encrypt video")
        print("  2   →  Decrypt video")
        print("  q   →  Quit")

        choice = input("> ").strip().lower()

        if choice in ('1', 'e', 'encrypt'):
            encrypt_video()
        elif choice in ('2', 'd', 'decrypt'):
            decrypt_video()
        elif choice in ('q', 'quit', 'exit'):
            print("\nDone. Bye!\n")
            break
        else:
            print("Enter 1, 2 or q")