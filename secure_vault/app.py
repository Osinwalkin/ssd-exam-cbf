import customtkinter as ctk
from . import crypto_utils
from . import storage

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Master Password"): # 'parent' is passed in
        super().__init__(parent)
        self.parent_app = parent # Store it as self.parent_app  <<< CORRECTION HERE
        self.title(title)
        self.lift()
        self.attributes("-topmost", True)
        self.grab_set()

        self.geometry("350x200")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        self.password_value = None 

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.label = ctk.CTkLabel(self.main_frame, text="Enter Master Password:")
        self.label.pack(pady=(0,10))

        self.password_entry = ctk.CTkEntry(self.main_frame, show="*", width=250)
        self.password_entry.pack(pady=(0,20))
        self.password_entry.bind("<Return>", self._submit_password_event)

        self.submit_button = ctk.CTkButton(self.main_frame, text="Unlock", command=self._submit_password)
        self.submit_button.pack(pady=(0,5))
        
        self.error_label = ctk.CTkLabel(self.main_frame, text="", text_color="red")
        self.error_label.pack()

        self.password_entry.focus_set()

    def _submit_password_event(self, event): 
        """Handles the <Return> key press in the password entry."""
        self._submit_password()

    def _submit_password(self): # event is passed when bound to <Return>
        entered_password = self.password_entry.get()
        if not entered_password:
            self.error_label.configure(text="Password cannot be empty.")
            return

        if self.parent_app.handle_password_submission(entered_password, self.error_label):
            self.password_value = entered_password 
            self.grab_release()
            self.destroy()
        else:
            self.password_value = None 
            # Error message set by parent_app.handle_password_submission

    def _on_closing(self):
        # This method is called when the dialog is closed (e.g., by clicking the X button)
        # We can set the password_value to None to indicate cancellation
        self.password_value = None
        self.grab_release()
        self.destroy()

    #def get_password(self):
        #self.master.wait_window(self) # Wait for dialog to close
        #return self.password_value

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Vault - Main")
        self.geometry("700x500")
        
        # Using self.withdraw() is generally good practice
        #self.withdraw() # Hide the main window initially 

        self.master_password_ok = False
        self.derived_encryption_key = None # To store the key derived from master_password

        # Determine if this is the first run using the storage module
        self.is_first_run = storage.is_first_run_check()
        if self.is_first_run:
            print("No existing setup detected (master_config.json not found). This is the first run.")
        else:
            print(f"Detected existing setup ({storage.MASTER_HASH_FILE} found). Not first run.")

        if self._perform_authentication():
            self.master_password_ok = True
            self.deiconify() # Show main window ONLY after successful auth
            self._setup_main_ui()
        else:
            # App will exit via __main__ block logic or if user closes password dialog
            # If _perform_authentication returns False, self.master_password_ok remains False
            # and the mainloop won't start.
            # If withdraw() was used, the app just closes. If not, an empty main window might have flashed.
            self.quit() # Ensure app exits if auth fails.

    def _perform_authentication(self):
        dialog_title = "Set Master Password" if self.is_first_run else "Enter Master Password"
        password_dialog = PasswordDialog(self, title=dialog_title)
        self.wait_window(password_dialog) # Wait for dialog to be destroyed

        # password_dialog.password_value is set by the dialog
        # self.derived_encryption_key will be set by a successful handle_password_submission
        if self.derived_encryption_key:
            print("Authentication successful: Encryption key derived.")
            return True
        else:
            print("Authentication failed or cancelled: Encryption key not derived.")
            return False


    def handle_password_submission(self, entered_password, error_label_widget):
        if self.is_first_run:
            # Basic password policy (can be more complex)
            if len(entered_password) < 8: # Enforce a minimum length
                error_label_widget.configure(text="Password must be at least 8 characters.")
                return False

            try:
                # 1. Hash the new master password (Argon2 handles salt internally)
                hashed_password_string = crypto_utils.hash_password(entered_password)
                
                # 2. Save the hashed password string
                storage.save_master_hash(hashed_password_string)

                # 3. Generate and save a new salt for encryption key derivation
                encryption_key_salt = crypto_utils.generate_salt(crypto_utils.ENCRYPTION_KEY_SALT_LEN)
                storage.save_encryption_key_salt(encryption_key_salt)

                # 4. Derive the encryption key using the plaintext password and the new salt
                self.derived_encryption_key = crypto_utils.derive_encryption_key(
                    entered_password, 
                    encryption_key_salt
                )
                # CRITICAL: Clear plaintext password from memory as much as possible
                # In Python, direct memory clearing is tricky. Reassigning is the best we can do.
                entered_password = None 
                
                self.is_first_run = False # No longer first run
                error_label_widget.configure(text="") # Clear error
                print("Master password setup successful. Encryption key derived.")
                return True
            except Exception as e:
                error_label_widget.configure(text=f"Setup error: {e}")
                print(f"Error during first run setup: {e}")
                # Potentially clean up partially created files if necessary
                return False
        else: # Not first run (verifying existing password)
            try:
                # 1. Load the stored Argon2 hash string
                stored_hashed_password_string = storage.load_master_hash()
                if not stored_hashed_password_string:
                    error_label_widget.configure(text="Error: Master password data not found.")
                    return False # Should not happen if not first_run, but good check

                # 2. Verify the entered password against the stored hash
                if crypto_utils.verify_password(stored_hashed_password_string, entered_password):
                    # 3. Load the salt for encryption key derivation
                    encryption_key_salt = storage.load_encryption_key_salt()
                    if not encryption_key_salt:
                        error_label_widget.configure(text="Error: Encryption key salt not found.")
                        # This is a critical error state, indicates data corruption/tampering
                        return False
                    
                    # 4. Derive the encryption key
                    self.derived_encryption_key = crypto_utils.derive_encryption_key(
                        entered_password,
                        encryption_key_salt
                    )
                    entered_password = None # Clear plaintext password

                    error_label_widget.configure(text="") # Clear error
                    print("Master password verified. Encryption key derived.")
                    return True
                else:
                    error_label_widget.configure(text="Invalid password.")
                    return False
            except Exception as e:
                error_label_widget.configure(text=f"Login error: {e}")
                print(f"Error during login: {e}")
                return False

    def _setup_main_ui(self):
        # Now we don't want to display the master password here
        self.label = ctk.CTkLabel(self, text="Welcome! Vault is Unlocked.")
        self.label.pack(pady=20, padx=20)

        self.add_secret_button = ctk.CTkButton(self, text="Add New Secret (TODO)", command=self.add_secret_dialog) # Added command
        self.add_secret_button.pack(pady=10)

        # We'll use a CTkTextbox to display secrets for now
        self.secrets_display = ctk.CTkTextbox(self, width=600, height=300)
        self.secrets_display.pack(pady=10, padx=10, fill="both", expand=True)
        self.secrets_display.insert("0.0", "Secrets will be listed here...\n")
        self.secrets_display.configure(state="disabled") # Make it read-only initially
        
        # Add a refresh/load button
        self.load_secrets_button = ctk.CTkButton(self, text="Load/Refresh Secrets (TODO)", command=self.load_and_display_secrets)
        self.load_secrets_button.pack(pady=5)

    def add_secret_dialog(self):
        # TODO: Implement a dialog to add a new secret (label and value)
        print("TODO: Open dialog to add a new secret")
        # This dialog will need to get label & secret, then call a method
        # to encrypt and save it using self.derived_encryption_key and storage.py functions
    
    def load_and_display_secrets(self):
        # TODO: Implement loading, decrypting, and displaying secrets
        print("TODO: Load, decrypt, and display secrets")
        # 1. Call storage.load_encrypted_secrets() -> returns encrypted blob
        # 2. If blob exists, call crypto_utils.decrypt_data(self.derived_encryption_key, blob)
        #    This will require implementing actual encryption/decryption using Fernet or AES-GCM
        #    and handling the structure of the stored secrets (e.g., a list of encrypted dicts).
        # 3. Parse the decrypted data (e.g., JSON list of {"label": "foo", "value": "bar"})
        # 4. Update self.secrets_display
        self.secrets_display.configure(state="normal")
        self.secrets_display.delete("1.0", "end")
        self.secrets_display.insert("0.0", "Secrets loaded (placeholder - actual data TODO)\n")
        self.secrets_display.configure(state="disabled")

if __name__ == "__main__":
    app = App() # Create the app instance

    if app.master_password_ok: # Check the flag set after authentication attempt
        app.mainloop() # Only run mainloop if authentication was successful
    else:
        print("Exiting: Authentication was not successful or was cancelled.")
        # If the app window was withdrawn and never deiconified,
        # it should just exit. If it was shown and then an error occurred,
        # app.destroy() might be needed, but here it's cleaner.