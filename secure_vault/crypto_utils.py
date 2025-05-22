import os
import base64
import argon2
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

# Argon2 config til password hashing
ARGON2_TIME_COST = 3    # antal iterations
ARGON2_MEMORY_COST = 65536 # størrelse i KB
ARGON2_PARALLELISM = 4  # Number of parallel threads
ARGON2_HASH_LEN = 32   # længde af hash i bytes
ARGON2_SALT_LEN = 16   # længde af salt i bytes

# PasswordHasher instance
ph = argon2.PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    encoding='utf-8' # give os utf-8 output
)

# Generer en salt til password hashing
def generate_salt(length: int = ARGON2_SALT_LEN) -> bytes:
    return os.urandom(length)

# Hash password med Argon2
# PasswordHasher håndterer salt generering internt og indlejrer det i hash-strengen
def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    hashed_password_full_string = ph.hash(password.encode('utf-8'))
    return hashed_password_full_string

# Verificer password mod en gemt Argon2 hash-streng
def verify_password(hashed_password_full_string: str, provided_password: str) -> bool:
    if not isinstance(provided_password, str):
        raise TypeError("Provided password must be a string.")
    try:
        ph.verify(hashed_password_full_string.encode('utf-8'), provided_password.encode('utf-8'))
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.VerificationError as e:
        print(f"Argon2 verification error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during password verification: {e}")
        return False

# Encryption key derivation
# Salt til at derivere krypteringsnøglen
ENCRYPTION_KEY_SALT_LEN = 16
ENCRYPTION_KEY_LEN = 32 # til AES-256

# Deriver en stabil krypteringsnøgle fra master password ved hjælp af HKDF
def derive_encryption_key(master_password: str, salt: bytes) -> bytes:
    if not isinstance(master_password, str):
        raise TypeError("Master password must be a string.")
    if not isinstance(salt, bytes) or len(salt) != ENCRYPTION_KEY_SALT_LEN:
        raise ValueError(f"Salt must be {ENCRYPTION_KEY_SALT_LEN} bytes.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=ENCRYPTION_KEY_LEN,
        salt=salt,
        info=b'secure-vault-encryption-key',
        backend=default_backend()
    )
    key = hkdf.derive(master_password.encode('utf-8'))
    return key

# Fernet key generation AEAD
# Konverterer en 32-byte raw key til en URL-sikker base64-encoded Fernet-nøgle
def get_fernet_key(raw_derived_key: bytes) -> bytes:
    if not isinstance(raw_derived_key, bytes) or len(raw_derived_key) != 32:
        raise ValueError("Raw derived key must be 32 bytes.")
    return base64.urlsafe_b64encode(raw_derived_key)

# Krypterer data ved hjælp af Fernet
def encrypt_data(fernet_key: bytes, plaintext_data: bytes) -> bytes:
    if not isinstance(plaintext_data, bytes):
        raise TypeError("Plaintext data must be bytes for encryption.")
    f = Fernet(fernet_key)
    ciphertext = f.encrypt(plaintext_data)
    return ciphertext

# Dekrypterer data ved hjælp af Fernet
# Returnerer decrypted bytes ved succes, None ved InvalidToken (manipulation/forkerte nøgler)
def decrypt_data(fernet_key: bytes, ciphertext_data: bytes) -> bytes | None:
    if not isinstance(ciphertext_data, bytes):
        raise TypeError("Ciphertext data must be bytes for decryption.")
    f = Fernet(fernet_key)
    try:
        decrypted_data = f.decrypt(ciphertext_data)
        return decrypted_data
    except InvalidToken:
        print("Decryption failed: Invalid token (data might be tampered or wrong key used).")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None # Or re-raise a custom app exception
