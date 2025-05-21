import json
import os

MASTER_HASH_FILE = "master_config.json" # Store salt and hash here
ENCRYPTION_KEY_SALT_FILE = "enc_key_salt.bin" # Separate file for encryption key salt
SECRETS_FILE = "secrets.dat" # Where encrypted secrets will go

def is_first_run_check() -> bool:
    """Checks if the master password hash file exists."""
    return not os.path.exists(MASTER_HASH_FILE)

def save_master_hash(hashed_password_string: str):
    """Saves the full Argon2 hashed password string."""
    # The string from Argon2 PasswordHasher already includes algo, params, salt, and hash
    data_to_save = {"master_password_hash_full": hashed_password_string}
    try:
        with open(MASTER_HASH_FILE, "w") as f:
            json.dump(data_to_save, f, indent=4)
        print(f"Master hash saved to {MASTER_HASH_FILE}")
    except IOError as e:
        print(f"Error saving master hash: {e}")
        # Consider raising a custom exception or returning False
        raise

def load_master_hash() -> str | None:
    """Loads the full Argon2 hashed password string. Returns None if not found or error."""
    if not os.path.exists(MASTER_HASH_FILE):
        return None
    try:
        with open(MASTER_HASH_FILE, "r") as f:
            data = json.load(f)
            return data.get("master_password_hash_full")
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading master hash: {e}")
        return None

# --- Encryption Key Salt Storage ---
def save_encryption_key_salt(salt: bytes):
    """Saves the salt used for deriving the encryption key."""
    try:
        with open(ENCRYPTION_KEY_SALT_FILE, "wb") as f:
            f.write(salt)
        print(f"Encryption key salt saved to {ENCRYPTION_KEY_SALT_FILE}")
    except IOError as e:
        print(f"Error saving encryption key salt: {e}")
        raise

def load_encryption_key_salt() -> bytes | None:
    """Loads the salt for deriving the encryption key. Returns None if not found or error."""
    if not os.path.exists(ENCRYPTION_KEY_SALT_FILE):
        return None
    try:
        with open(ENCRYPTION_KEY_SALT_FILE, "rb") as f:
            return f.read()
    except IOError as e:
        print(f"Error loading encryption key salt: {e}")
        return None

# encrypted secrets storage
def save_encrypted_secrets(encrypted_data_blob: bytes):
    """Saves the blob of encrypted secrets to the secrets file."""
    try:
        with open(SECRETS_FILE, "wb") as f: # Write in binary mode
            f.write(encrypted_data_blob)
        print(f"Encrypted secrets saved to {SECRETS_FILE}")
    except IOError as e:
        print(f"Error saving encrypted secrets: {e}")
        # Consider raising a custom app exception for the UI to handle
        raise # Re-raise for now

def load_encrypted_secrets() -> bytes | None:
    """
    Loads the blob of encrypted secrets from the secrets file.
    Returns the byte string if the file exists, None otherwise.
    """
    if not os.path.exists(SECRETS_FILE):
        print(f"Secrets file ({SECRETS_FILE}) not found. Assuming no secrets yet.")
        return None # No secrets file yet, perfectly normal for a new vault
    try:
        with open(SECRETS_FILE, "rb") as f: # Read in binary mode
            return f.read()
    except IOError as e:
        print(f"Error loading encrypted secrets: {e}")
        # Consider raising a custom app exception
        return None # Or re-raise