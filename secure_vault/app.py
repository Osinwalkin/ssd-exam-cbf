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
        #self.withdraw() # Hide the main window initially

        self.master_password_ok = False # Flag to indicate successful authentication
        self.master_password_plaintext = None # Store plaintext only briefly if needed for key derivation
        # self.is_first_run = True # Placeholder, will be determined by storage check

        # This is where you'd check if the master password exists
        try:
            # This is where you'd call storage.check_if_master_password_exists() or similar
            # For now, let's simulate it. If a file "master_hash.json" exists, it's not first run.
            with open("master_hash.json", "r") as f: # Replace with actual storage check
                self.is_first_run = False
            print("Detected existing setup (master_hash.json found). Not first run.")
        except FileNotFoundError:
            self.is_first_run = True
            print("No existing setup detected. This is the first run.")

        if self._perform_authentication():
            self.master_password_ok = True
            self.deiconify() # Show main window
            self._setup_main_ui()
        else:
            # App will exit via __main__ block logic
            pass

    def _perform_authentication(self):
        """
        Manages the display of the password dialog and processing its result.
        Returns True if authentication is successful, False otherwise.
        """
        dialog_title = "Set Master Password" if self.is_first_run else "Enter Master Password"
        
        password_dialog = PasswordDialog(self, title=dialog_title)
        self.wait_window(password_dialog) # Wait for dialog to be destroyed

        if self.master_password_plaintext: # This will be set by a successful handle_password_submission
            print("Authentication successful via _perform_authentication.")
            return True
        else:
            print("Authentication failed or cancelled via _perform_authentication.")
            return False


    def handle_password_submission(self, entered_password, error_label_widget):
        """
        Called by PasswordDialog.
        Handles setting or verifying the master password.
        Updates the error_label_widget in the dialog directly.
        Returns True on success, False on failure.
        """
        if self.is_first_run:
            if len(entered_password) < 1: # Simpler check for testing now
                error_label_widget.configure(text="Password must be at least 1 characters (test).")
                return False
            
            print(f"Setting up new master password (placeholder): {entered_password}")
            # TODO:
            # 1. Generate salt
            # 2. Hash password with salt (using crypto_utils.hash_password)
            # 3. Store salt and hash (using storage.save_master_password_hash)
            # 4. Derive encryption key from entered_password, store in self.derived_key
            self.master_password_plaintext = entered_password # Store temporarily
            self.is_first_run = False 
            error_label_widget.configure(text="") # Clear error
            return True
        else: # Not first run (verifying existing password)
            print(f"Verifying existing master password (placeholder): {entered_password}")
            # TODO:
            # 1. Load salt and hash (using storage.load_master_password_hash)
            # 2. Verify entered_password against stored hash (using crypto_utils.verify_password)
            # 3. If verified, derive encryption key, store in self.derived_key
            
            # Simulate verification
            if entered_password == "test": # Placeholder for correct password
                self.master_password_plaintext = entered_password
                error_label_widget.configure(text="") # Clear error
                return True
            else:
                error_label_widget.configure(text="Invalid password.")
                return False

    def _setup_main_ui(self):
        self.label = ctk.CTkLabel(self, text=f"Welcome! Vault is Unlocked.\nMaster Password (temp): {self.master_password_plaintext}")
        self.label.pack(pady=20, padx=20)

        self.add_secret_button = ctk.CTkButton(self, text="Add New Secret (TODO)")
        self.add_secret_button.pack(pady=10)

        self.view_secrets_listbox = ctk.CTkTextbox(self, width=400, height=200)
        self.view_secrets_listbox.pack(pady=10)
        self.view_secrets_listbox.insert("0.0", "Secrets will be listed here (TODO)")
        self.view_secrets_listbox.configure(state="disabled")

if __name__ == "__main__":
    app = App() # Create the app instance

    if app.master_password_ok: # Check the flag set after authentication attempt
        app.mainloop() # Only run mainloop if authentication was successful
    else:
        print("Exiting: Authentication was not successful or was cancelled.")
        # If the app window was withdrawn and never deiconified,
        # it should just exit. If it was shown and then an error occurred,
        # app.destroy() might be needed, but here it's cleaner.