import os
import argon2 # For password hashing
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
# For AEAD encryption (will add later)
# from cryptography.fernet import Fernet 

# Argon2 Parameters (good defaults, can be tuned)
ARGON2_TIME_COST = 3      # Number of iterations
ARGON2_MEMORY_COST = 65536 # KiB (64 MiB)
ARGON2_PARALLELISM = 4  # Number of parallel threads
ARGON2_HASH_LEN = 32    # Bytes
ARGON2_SALT_LEN = 16    # Bytes

# PasswordHasher instance
ph = argon2.PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    encoding='utf-8' # Store hash as utf-8 string
)

def generate_salt(length: int = ARGON2_SALT_LEN) -> bytes:
    """Generates a cryptographically strong random salt."""
    return os.urandom(length)

def hash_password(password: str) -> str:
    """
    Hashes a password using Argon2id with a provided salt.
    Note: Argon2's PasswordHasher class can also generate its own salt
    if you just call ph.hash(password), and ph.verify(hash, password)
    can extract the salt. This simplifies storage as you store one string.
    Let's use that simpler approach provided by the library.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    # The library handles salt generation internally and embeds it in the hash string
    hashed_password_full_string = ph.hash(password.encode('utf-8'))
    return hashed_password_full_string # This string contains algo, params, salt, and hash

def verify_password(hashed_password_full_string: str, provided_password: str) -> bool:
    """
    Verifies a provided password against a stored Argon2 hash string.
    The hash string must contain the embedded salt and parameters.
    """
    if not isinstance(provided_password, str):
        raise TypeError("Provided password must be a string.")
    try:
        ph.verify(hashed_password_full_string.encode('utf-8'), provided_password.encode('utf-8'))
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.VerificationError as e: # Other errors during verification
        print(f"Argon2 verification error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during password verification: {e}")
        return False

# --- Placeholder for Key Derivation and Encryption (will add later today/tomorrow) ---
ENCRYPTION_KEY_SALT_LEN = 16 # For deriving encryption key
ENCRYPTION_KEY_LEN = 32      # For AES-256

def derive_encryption_key(master_password: str, salt: bytes) -> bytes:
    """Derives a stable encryption key from the master password using HKDF."""
    if not isinstance(master_password, str):
        raise TypeError("Master password must be a string.")
    if not isinstance(salt, bytes) or len(salt) != ENCRYPTION_KEY_SALT_LEN:
        raise ValueError(f"Salt must be {ENCRYPTION_KEY_SALT_LEN} bytes.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=ENCRYPTION_KEY_LEN,
        salt=salt,
        info=b'secure-vault-encryption-key', # Context-specific info
        backend=default_backend()
    )
    key = hkdf.derive(master_password.encode('utf-8'))
    return key

# def encrypt_data(key: bytes, plaintext_data: bytes) -> bytes:
#     f = Fernet(key) # Fernet key must be urlsafe_base64_encode(32 random bytes)
                       # Our derived key is raw 32 bytes, need to encode it for Fernet
#     return f.encrypt(plaintext_data)

# def decrypt_data(key: bytes, ciphertext_data: bytes) -> bytes:
#     f = Fernet(key)
#     return f.decrypt(ciphertext_data)