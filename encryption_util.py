"""
encryption_util.py – Unified file encryption/decryption for DgEvidenceLocker
Hybrid AES-256-CBC + ChaCha20-Poly1305 (supports files of any size)
Used automatically on every evidence upload.
"""
import os
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# ── Master encryption password for server-side storage ──────────────────────
# In production, load this from an environment variable / secrets manager.
SERVER_ENC_PASSWORD = os.environ.get('SERVER_ENC_PASSWORD', '')

CHUNK_SIZE = 64 * 1024 * 1024   # 64 MB chunks (safe for most uploads)
ENC_EXT    = '.dgenc'            # our unified encrypted extension


def _derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(password.encode('utf-8'))


def compute_sha256(filepath: str) -> str:
    """Return hex SHA-256 hash of the original file (before encryption)."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def encrypt_evidence(src_path: str, password: str) -> str:
    """
    Encrypt src_path using AES-256+ChaCha20 hybrid.
    Returns path of the encrypted file (src_path + '.dgenc').
    Original file is removed after successful encryption.
    """
    chacha_key  = os.urandom(32)
    base_nonce  = os.urandom(8)
    salt        = os.urandom(32)
    aes_iv      = os.urandom(16)
    master_key  = _derive_master_key(password, salt)

    to_protect = chacha_key + base_nonce          # 40 bytes
    padder = padding.PKCS7(128).padder()
    padded = padder.update(to_protect) + padder.finalize()

    cipher = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv))
    encryptor = cipher.encryptor()
    enc_meta = encryptor.update(padded) + encryptor.finalize()  # 48 bytes

    out_path = src_path + ENC_EXT
    chacha   = ChaCha20Poly1305(chacha_key)
    nonce_counter = 0

    try:
        with open(src_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
            # Header: salt(32) + aes_iv(16) + enc_meta(48) = 96 bytes
            f_out.write(salt + aes_iv + enc_meta)
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                nonce = base_nonce + nonce_counter.to_bytes(4, 'big')
                f_out.write(chacha.encrypt(nonce, chunk, None))
                nonce_counter += 1

        # Remove original plaintext file
        os.remove(src_path)
        return out_path

    except Exception as e:
        if os.path.exists(out_path):
            try:
                os.remove(out_path)
            except Exception:
                pass
        raise RuntimeError(f'Encryption failed: {e}') from e


def decrypt_evidence(enc_path: str, dest_path: str, password: str) -> str:
    """
    Decrypt enc_path to dest_path.
    Returns dest_path on success, raises RuntimeError on failure.
    """
    try:
        with open(enc_path, 'rb') as f:
            header = f.read(96)
            if len(header) != 96:
                raise RuntimeError('Encrypted file header is incomplete or corrupted.')

        salt      = header[0:32]
        aes_iv    = header[32:48]
        enc_meta  = header[48:96]

        master_key = _derive_master_key(password, salt)

        cipher    = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv))
        decryptor = cipher.decryptor()
        padded    = decryptor.update(enc_meta) + decryptor.finalize()

        try:
            unpadder = padding.PKCS7(128).unpadder()
            metadata = unpadder.update(padded) + unpadder.finalize()
        except ValueError:
            raise RuntimeError('Wrong password or corrupted header.')

        chacha_key = metadata[0:32]
        base_nonce = metadata[32:40]

        chacha        = ChaCha20Poly1305(chacha_key)
        nonce_counter = 0

        os.makedirs(os.path.dirname(dest_path) if os.path.dirname(dest_path) else '.', exist_ok=True)

        with open(enc_path, 'rb') as f_in, open(dest_path, 'wb') as f_out:
            f_in.seek(96)  # skip header
            while True:
                chunk = f_in.read(CHUNK_SIZE + 16)  # +16 for Poly1305 tag
                if not chunk:
                    break
                nonce = base_nonce + nonce_counter.to_bytes(4, 'big')
                try:
                    f_out.write(chacha.decrypt(nonce, chunk, None))
                except InvalidTag:
                    raise RuntimeError('Authentication failed – file may be tampered with.')
                nonce_counter += 1

        return dest_path

    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f'Decryption failed: {e}') from e


def validate_password(enc_path: str, password: str) -> bool:
    """
    Verify if the password is correct by attempting to decrypt the header.
    Does NOT decrypt the entire file.
    """
    try:
        if not os.path.exists(enc_path):
            return False
            
        with open(enc_path, 'rb') as f:
            header = f.read(96)
            if len(header) != 96:
                return False

        salt      = header[0:32]
        aes_iv    = header[32:48]
        enc_meta  = header[48:96]

        master_key = _derive_master_key(password, salt)
        cipher    = Cipher(algorithms.AES(master_key), modes.CBC(aes_iv))
        decryptor = cipher.decryptor()
        padded    = decryptor.update(enc_meta) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(padded) + unpadder.finalize()
        return True
    except Exception:
        return False


def verify_integrity(enc_path: str, expected_hash: str, password: str) -> bool:
    """
    Decrypt to a temp buffer and verify SHA-256 matches expected_hash.
    Returns True if integrity check passes.
    """
    import tempfile
    tmp = tempfile.mktemp(suffix='.verify')
    try:
        decrypt_evidence(enc_path, tmp, password)
        # Assuming compute_sha256 is defined above in the file
        h = hashlib.sha256()
        with open(tmp, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        actual = h.hexdigest()
        return actual == expected_hash
    except Exception:
        return False
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
