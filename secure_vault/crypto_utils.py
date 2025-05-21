import os
import base64
import argon2 # For password hashing
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

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

def get_fernet_key(raw_derived_key: bytes) -> bytes:
    """Converts a 32-byte raw key to a URL-safe base64 encoded Fernet key."""
    if not isinstance(raw_derived_key, bytes) or len(raw_derived_key) != 32:
        raise ValueError("Raw derived key must be 32 bytes.")
    return base64.urlsafe_b64encode(raw_derived_key)

def encrypt_data(fernet_key: bytes, plaintext_data: bytes) -> bytes:
    """Encrypts data using Fernet."""
    if not isinstance(plaintext_data, bytes):
        raise TypeError("Plaintext data must be bytes for encryption.")
    f = Fernet(fernet_key)
    ciphertext = f.encrypt(plaintext_data)
    return ciphertext

def decrypt_data(fernet_key: bytes, ciphertext_data: bytes) -> bytes | None:
    """
    Decrypts data using Fernet.
    Returns decrypted bytes on success, None on InvalidToken (tampering/wrong key).
    """
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
