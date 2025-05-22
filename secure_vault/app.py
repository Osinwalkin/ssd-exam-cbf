# GUI ting til Secure Vault appen
import customtkinter as ctk
import tkinter.messagebox as messagebox

import json
from . import crypto_utils
from . import storage

# udseende af appen
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Dialog vindue til at indtaste master password
class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Master Password"):
        super().__init__(parent)
        self.parent_app = parent
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

    # Håndterer enter knappetryk i password feltet
    def _submit_password_event(self, event): 
        self._submit_password()

    # Håndterer submit knappen
    def _submit_password(self):
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

    # Håndterer lukning af dialog vinduet
    def _on_closing(self):
        self.password_value = None
        self.grab_release()
        self.destroy()

# Tilføjelse af ny secret vindue
# Dette vindue åbnes når brugeren vil tilføje en ny secret
class AddSecretDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent_app = parent
        self.title("Add New Secret")
        self.lift()
        self.attributes("-topmost", True)
        self.grab_set()
        self.geometry("400x250") # Adjusted size
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        self.new_secret_data = None # To store {"label": str, "value": str}

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(self.main_frame, text="Label:").pack(anchor="w")
        self.label_entry = ctk.CTkEntry(self.main_frame, width=300)
        self.label_entry.pack(fill="x", pady=(0,10))

        ctk.CTkLabel(self.main_frame, text="Secret Value:").pack(anchor="w")
        self.value_entry = ctk.CTkEntry(self.main_frame, width=300, show="*") # Show '*' for secret
        self.value_entry.pack(fill="x", pady=(0,10))

        self.show_secret_var = ctk.BooleanVar()
        self.show_secret_checkbox = ctk.CTkCheckBox(self.main_frame, text="Show secret",
                                                    variable=self.show_secret_var,
                                                    command=self._toggle_secret_visibility)
        self.show_secret_checkbox.pack(anchor="w", pady=(0, 15))

        self.save_button = ctk.CTkButton(self.main_frame, text="Save Secret", command=self._save_secret)
        self.save_button.pack(side="right", padx=(10,0))
        self.cancel_button = ctk.CTkButton(self.main_frame, text="Cancel", command=self._on_closing, fg_color="gray")
        self.cancel_button.pack(side="right")
        
        self.error_label = ctk.CTkLabel(self.main_frame, text="", text_color="red")

        self.label_entry.focus_set()
        self.value_entry.bind("<Return>", self._save_secret_event)

    def _toggle_secret_visibility(self):
        if self.show_secret_var.get():
            self.value_entry.configure(show="")
        else:
            self.value_entry.configure(show="*")

    def _save_secret_event(self, event):
        self._save_secret()

    # Validerer input og gemmer secret hvis det er gyldigt
    def _save_secret(self):
        label = self.label_entry.get().strip()
        value = self.value_entry.get()

        if not label or not value:
            print("Error: Label and Secret Value cannot be empty.")
            messagebox.showerror("Input Error", "Label and Secret Value cannot be empty.", parent=self)
            return

        self.new_secret_data = {"label": label, "value": value}
        self.grab_release()
        self.destroy()

    def _on_closing(self):
        self.new_secret_data = None
        self.grab_release()
        self.destroy()


# Hovedvinduet for Secure Vault appen
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Vault - Main")
        self.geometry("700x500")
        
        # gemmer vinduet indtil password er autentificeret (Har kommenteret ud fordi det ikke virker lige nu)
        #self.withdraw() 

        # variabler til at gemme master password og krypteringsnøgle
        self.master_password_ok = False
        self.derived_encryption_key = None
        self.fernet_handler = None

        # Tjekker om det er første gang appen køres
        self.is_first_run = storage.is_first_run_check()
        if self.is_first_run:
            print("No existing setup detected (master_config.json not found). This is the first run.")
        else:
            print(f"Detected existing setup ({storage.MASTER_HASH_FILE} found). Not first run.")

        if self._perform_authentication():
            self.master_password_ok = True
            self.deiconify() 
            self._setup_main_ui()
        else:
            self.quit()  

    # Håndterer autentificering af master password
    def _perform_authentication(self):
        dialog_title = "Set Master Password" if self.is_first_run else "Enter Master Password"
        password_dialog = PasswordDialog(self, title=dialog_title)
        self.wait_window(password_dialog) 

        if self.fernet_handler:
            print("Authentication successful: Fernet key prepared.")
            return True
        else:
            print("Authentication failed or cancelled: Fernet key not prepared.")
            return False


    # Håndterer logic for opsætning (first run) eller verificering af master password
    # Metoden bliver kaldt fra PasswordDialog
    def handle_password_submission(self, entered_password, error_label_widget):
        if self.is_first_run:
            # Opsætning af master password
            if len(entered_password) < 8:
                error_label_widget.configure(text="Password must be at least 8 characters.")
                return False
            try:
                # Hash det nye master password og gem det (Argon2)
                hashed_password_string = crypto_utils.hash_password(entered_password)
                storage.save_master_hash(hashed_password_string)

                # Gem salt til krypteringsnøgle
                # (HKDF salt genereres internt i crypto_utils)
                encryption_key_salt = crypto_utils.generate_salt(crypto_utils.ENCRYPTION_KEY_SALT_LEN)
                storage.save_encryption_key_salt(encryption_key_salt)

                # Deriver krypteringsnøgle fra plaintext password og og HDKF salt
                self.derived_encryption_key = crypto_utils.derive_encryption_key(
                    entered_password, encryption_key_salt
                )
                # Konverter krypteringsnøglen til Fernet-nøgle
                self.fernet_handler = crypto_utils.get_fernet_key(self.derived_encryption_key)

                # Variabler til at nulstille password og status
                entered_password = None 
                self.is_first_run = False
                error_label_widget.configure(text="")
                print("Master password setup successful. Fernet key prepared.")
                return True
            except Exception as e:
                error_label_widget.configure(text=f"Setup error: {e}")
                print(f"Error during first run setup: {e}")
                return False
        else:
            # IKKE first run: Verificer master password
            try:
                # Hent den gemte Argon2 hash af master password
                stored_hashed_password_string = storage.load_master_hash()
                if not stored_hashed_password_string:
                    error_label_widget.configure(text="Error: Master password data not found.")
                    return False
                
                # Verificer det indtastede password mod den gemte hash
                if crypto_utils.verify_password(stored_hashed_password_string, entered_password):
                    # Hent salt til krypteringsnøgle
                    encryption_key_salt = storage.load_encryption_key_salt()
                    if not encryption_key_salt:
                        error_label_widget.configure(text="Error: Encryption key salt not found.")
                        return False # Critical error
                    
                    # Deriver krypteringsnøgle fra det indtastede password og salt
                    self.derived_encryption_key = crypto_utils.derive_encryption_key(
                        entered_password, 
                        encryption_key_salt
                    )
                    # Konverter krypteringsnøglen til Fernet-nøgle
                    self.fernet_handler = crypto_utils.get_fernet_key(self.derived_encryption_key)

                    entered_password = None
                    error_label_widget.configure(text="")
                    print("Master password verified. Fernet key prepared.")
                    return True
                else:
                    error_label_widget.configure(text="Invalid password.")
                    return False
            except Exception as e:
                error_label_widget.configure(text=f"Login error: {e}")
                print(f"Error during login: {e}")
                return False

    # Håndterer opsætning af UI efter autentificering
    def _setup_main_ui(self):
        self.label = ctk.CTkLabel(self, text="Welcome! Vault is Unlocked.")
        self.label.pack(pady=20, padx=20)

        self.add_secret_button = ctk.CTkButton(self, text="Add New Secret", command=self.add_secret_dialog)
        self.add_secret_button.pack(pady=10)

        self.secrets_display = ctk.CTkTextbox(self, width=600, height=300)
        self.secrets_display.pack(pady=10, padx=10, fill="both", expand=True)
        self.secrets_display.configure(state="disabled") 
        
        self.load_secrets_button = ctk.CTkButton(self, text="Load/Refresh Secrets", command=self.load_and_display_secrets)
        self.load_secrets_button.pack(pady=5) 

        self.load_and_display_secrets()
    
    # Loader secrets fra filen og dekrypterer dem
    # Returnerer en liste af secrets
    def _get_decrypted_secrets_list(self) -> list:
        if not self.fernet_handler:
            print("Error: Encryption key not available for decryption (fernet_handler not set).")
            messagebox.showerror("Internal Error", "Encryption key not available.", parent=self) # Optional
            return []

        encrypted_blob = storage.load_encrypted_secrets()
        if not encrypted_blob:
            return [] 

        try:
            # Dekrypterer den gemte blob med Fernet
            decrypted_json_bytes = crypto_utils.decrypt_data(self.fernet_handler, encrypted_blob)
            if decrypted_json_bytes:
                # Parser JSON data til Python liste
                secrets_list = json.loads(decrypted_json_bytes.decode('utf-8'))
                return secrets_list
            else:
                messagebox.showerror("Decryption Error",
                                  "Failed to decrypt secrets. File may be corrupt, or the wrong master password was used previously (if so, delete config files and restart).",
                                  parent=self)
                return [] 
        except json.JSONDecodeError:
            print("Error: Could not decode decrypted secrets (not valid JSON).")
            messagebox.showerror("Data Error", "Corrupted secret data format.", parent=self)
            return []
        except Exception as e:
            print(f"An unexpected error occurred while getting decrypted secrets: {e}")
            messagebox.showerror("Error", f"Unexpected error during decryption: {e}", parent=self)
            return []
        
    # Gemmer secrets til en JSON fil efter kryptering
    def _save_secrets_list(self, secrets_list: list) -> bool:
        if not self.fernet_handler:
            print("Error: Encryption key not available for encryption (fernet_handler not set).")
            messagebox.showerror("Internal Error", "Encryption key not available for saving.", parent=self)
            return False
        
        try:
            json_bytes = json.dumps(secrets_list, indent=4).encode('utf-8')
            encrypted_blob = crypto_utils.encrypt_data(self.fernet_handler, json_bytes)
            storage.save_encrypted_secrets(encrypted_blob)
            return True
        except Exception as e:
            print(f"Error saving secrets: {e}")
            messagebox.showerror("Save Error", f"Could not save secrets: {e}", parent=self)
            return False
        
    # Åbner dialog vindue til at tilføje en ny secret
    def add_secret_dialog(self):
        if not self.fernet_handler: 
            messagebox.showerror("Error", "Cannot add secret: Vault not properly initialized.", icon="error", parent=self)
            return

        dialog = AddSecretDialog(self)
        self.wait_window(dialog) 

        new_data = dialog.new_secret_data 
        if new_data:
            secrets = self._get_decrypted_secrets_list()
            if any(s['label'].lower() == new_data['label'].lower() for s in secrets):
                messagebox.showwarning("Duplicate Label",
                                  f"A secret with the label '{new_data['label']}' already exists.",
                                  icon="warning", parent=self)
                return

            secrets.append(new_data)
            if self._save_secrets_list(secrets):
                print(f"Secret '{new_data['label']}' added and saved.")
                self.load_and_display_secrets() 
            else:
                print("Failed to save the new secret after adding.")
    
    # Loader og viser secrets i tekstfeltet, man kan klikke på den blå label for at kopiere til clipboard
    # Ikke særlig pænt men det virker hvis man trykker på det blå highlightede tekst
    def load_and_display_secrets(self):
        self.secrets_display.configure(state="normal")
        self.secrets_display.delete("1.0", "end")

        secrets = self._get_decrypted_secrets_list()

        if not secrets:
            self.secrets_display.insert("0.0", "No secrets found or vault is empty.\n")
        else:
            header = f"{'Label':<30} | {'Value (click label to copy)':<50}\n"
            self.secrets_display.insert("0.0", header)
            self.secrets_display.insert("end", "-"*len(header.strip()) + "\n")
            for i, secret_item in enumerate(secrets):
                label = secret_item.get('label', 'N/A')
                display_text = f"{label:<30} | {'*' * 10:<50}\n"
                
                tag_name = f"secret_tag_{i}"
                current_pos = self.secrets_display.index("end-1c")
                self.secrets_display.insert("end", display_text)

                line_start_index = self.secrets_display.index(f"end-{len(display_text.rstrip())+1}c")
                line_end_index = self.secrets_display.index("end-1c")
                self.secrets_display.tag_add(tag_name, line_start_index, line_end_index)

                self.secrets_display.tag_config(tag_name, foreground="cyan") 
                self.secrets_display.tag_bind(
                    tag_name, 
                    "<Button-1>", 
                    lambda e, s_val=secret_item.get('value'): self.copy_secret_to_clipboard(s_val)
                )
        
        self.secrets_display.configure(state="disabled")

    def copy_secret_to_clipboard(self, secret_value: str):
        if secret_value:
            try:
                self.clipboard_clear()
                self.clipboard_append(secret_value)
                print(f"Secret copied to clipboard.")
                status_label = ctk.CTkLabel(self, text="Copied to clipboard!", text_color="green", fg_color=("gray80", "gray20")) # Added bg for visibility
                status_label.place(relx=0.5, rely=0.05, anchor="center") # Place at top
                self.after(2000, status_label.destroy) 

            except Exception as e:
                print(f"Error copying to clipboard: {e}")
                messagebox.showwarning("Clipboard Error", "Could not copy to clipboard.", icon="warning", parent=self)
        else:
            print("No secret value to copy (should not happen if called from UI).")

if __name__ == "__main__":
    app = App()
    if app.master_password_ok:
        app.mainloop()
    else:
        print("Exiting: Authentication was not successful or was cancelled.")