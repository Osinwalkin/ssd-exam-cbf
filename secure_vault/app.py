import customtkinter as ctk

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Vault")
        self.geometry("400x300")

        self.label = ctk.CTkLabel(self, text="Secure Desktop Vault - Initial Setup")
        self.label.pack(pady=20, padx=20)

if __name__ == "__main__":
    app = App()
    app.mainloop()