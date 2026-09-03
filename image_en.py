# minimal_aes256_encrypt_decrypt.py
from cryptography.fernet import Fernet
import base64
import os
import getpass

print("Simple AES image encrypt/decrypt (Fernet)\n")

key_file = "image_key.key"

if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    print("→ Created new key file: image_key.key  (KEEP IT SAFE!)")
else:
    with open(key_file, "rb") as f:
        key = f.read()
    print("Using existing key: image_key.key")

f = Fernet(key)

mode = input("e = encrypt    d = decrypt   → ").strip().lower()

pw = getpass.getpass("Password (just for confirmation): ")  # optional

if mode == 'e':
    infile = input("Image path: ").strip()
    outfile = infile + ".enc"
    with open(infile, "rb") as img:
        data = img.read()
    encrypted = f.encrypt(data)
    with open(outfile, "wb") as out:
        out.write(encrypted)
    print(f"Done → {outfile}")

elif mode == 'd':
    infile = input("Encrypted file (.enc): ").strip()
    outfile = infile.replace(".enc", "_decrypted.jpg")
    with open(infile, "rb") as enc:
        data = enc.read()
    try:
        decrypted = f.decrypt(data)
        with open(outfile, "wb") as out:
            out.write(decrypted)
        print(f"Done → {outfile}")
    except Exception as e:
        print("Failed — most likely wrong key/file damaged")
        print(e)

else:
    print("Only e or d allowed.")