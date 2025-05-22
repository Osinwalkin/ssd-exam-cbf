import json
import os

# Fil navne til at gemme secrets og/eller konfigurationer, passwords etc...
# Normalt gemmes disse et sikkert sted, men til den her opgave ligger de i root folderen så vi kan se dem og deres resultater
MASTER_HASH_FILE = "master_config.json" # salt og hash
ENCRYPTION_KEY_SALT_FILE = "enc_key_salt.bin"
SECRETS_FILE = "secrets.dat" # hvor de krypterede secrets gemmes


# - Master Password Hash Storage

# Tjekker om master password hash filen eksisterer
def is_first_run_check() -> bool:
    return not os.path.exists(MASTER_HASH_FILE)

# Gemmer den fulde Argon2 hash af master password som string
def save_master_hash(hashed_password_string: str):
    data_to_save = {"master_password_hash_full": hashed_password_string}
    try:
        with open(MASTER_HASH_FILE, "w") as f:
            json.dump(data_to_save, f, indent=4)
        print(f"Master hash saved to {MASTER_HASH_FILE}")
    except IOError as e:
        print(f"Error saving master hash: {e}")
        raise

# Loader den fulde Argon2 hash af master password som string, returnerer None hvis ikke fundet eller fejl
def load_master_hash() -> str | None:
    if not os.path.exists(MASTER_HASH_FILE):
        return None
    try:
        with open(MASTER_HASH_FILE, "r") as f:
            data = json.load(f)
            return data.get("master_password_hash_full")
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading master hash: {e}")
        return None


# - Encryption Key Salt Storage

# Gemmer salt til at derive krypteringsnøglen
def save_encryption_key_salt(salt: bytes):
    try:
        with open(ENCRYPTION_KEY_SALT_FILE, "wb") as f:
            f.write(salt)
        print(f"Encryption key salt saved to {ENCRYPTION_KEY_SALT_FILE}")
    except IOError as e:
        print(f"Error saving encryption key salt: {e}")
        raise

# Loader salt til at derive krypteringsnøglen, returnerer None hvis ikke fundet eller fejl
def load_encryption_key_salt() -> bytes | None:
    if not os.path.exists(ENCRYPTION_KEY_SALT_FILE):
        return None
    try:
        with open(ENCRYPTION_KEY_SALT_FILE, "rb") as f:
            return f.read()
    except IOError as e:
        print(f"Error loading encryption key salt: {e}")
        return None


# - Krypterede secrets Storage

# Gemmer krypterede secrets til filen
def save_encrypted_secrets(encrypted_data_blob: bytes):
    try:
        with open(SECRETS_FILE, "wb") as f:
            f.write(encrypted_data_blob)
        print(f"Encrypted secrets saved to {SECRETS_FILE}")
    except IOError as e:
        print(f"Error saving encrypted secrets: {e}")
        raise

# Loader krypterede secrets fra filen, returnerer byte string hvis filen eksisterer, None hvis ikke
def load_encrypted_secrets() -> bytes | None:
    if not os.path.exists(SECRETS_FILE):
        print(f"Secrets file ({SECRETS_FILE}) not found. Assuming no secrets yet.")
        return None
    try:
        with open(SECRETS_FILE, "rb") as f:
            return f.read()
    except IOError as e:
        print(f"Error loading encrypted secrets: {e}")
        return None