import customtkinter as ctk
from tkinter import filedialog, messagebox


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window General Settings
        self.title("🛡️ Cryptograph")
        self.geometry("600x400")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Variables
        self.selected_file = ctk.StringVar(value="No file selected")
        self.algorithm = ctk.StringVar(value="AES")
        self.mode = ctk.StringVar(value="CBC")
        self.password = ctk.StringVar(value="")
        self.status = ctk.StringVar(value="Ready")

        # UI Components
        self.create_widgets()

    def create_widgets(self):
        # ===== Header =====
        header = ctk.CTkLabel(self, text="🛡️ Cryptograph", font=("Arial", 24, "bold"))
        header.pack(pady=(20, 10))

        # ===== File selection =====
        file_frame = ctk.CTkFrame(self)
        file_frame.pack(fill="x", padx=20, pady=10)

        browse_btn = ctk.CTkButton(file_frame, text="Select File", command=self.browse_file)
        browse_btn.pack(side="left", padx=10, pady=10)

        file_label = ctk.CTkLabel(file_frame, textvariable=self.selected_file, anchor="w")
        file_label.pack(side="left", padx=10, fill="x", expand=True)

        # ===== Algorithm & Mode =====
        options_frame = ctk.CTkFrame(self)
        options_frame.pack(fill="x", padx=20, pady=10)

        algo_label = ctk.CTkLabel(options_frame, text="Algorithm:")
        algo_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

        algo_menu = ctk.CTkOptionMenu(options_frame, values=["AES", "DES", "3DES"], variable=self.algorithm)
        algo_menu.grid(row=0, column=1, padx=10, pady=5)

        mode_label = ctk.CTkLabel(options_frame, text="Mode:")
        mode_label.grid(row=0, column=2, padx=10, pady=5, sticky="e")

        mode_menu = ctk.CTkOptionMenu(options_frame, values=["CBC", "ECB"], variable=self.mode)
        mode_menu.grid(row=0, column=3, padx=10, pady=5)

        # ===== Password =====
        password_label = ctk.CTkLabel(self, text="Password:")
        password_label.pack(anchor="w", padx=30, pady=(10, 0))

        password_entry = ctk.CTkEntry(self, textvariable=self.password, show="*")
        password_entry.pack(fill="x", padx=30, pady=(0, 15))

        # ===== Action Buttons =====
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(pady=10)

        encrypt_btn = ctk.CTkButton(button_frame, text="🔒 Encrypt", command=self.encrypt_action, width=120)
        encrypt_btn.grid(row=0, column=0, padx=20)

        decrypt_btn = ctk.CTkButton(button_frame, text="🔓 Decrypt", command=self.decrypt_action, width=120)
        decrypt_btn.grid(row=0, column=1, padx=20)

        # ===== Status Bar =====
        status_label = ctk.CTkLabel(self, textvariable=self.status, text_color="gray", anchor="w")
        status_label.pack(fill="x", padx=20, pady=(10, 0))

    # ===== Event Functions =====

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select a file")
        if file_path:
            self.selected_file.set(file_path)
            self.status.set("File selected ✅")

    def encrypt_action(self):
        if not self.password.get():
            messagebox.showwarning("Warning", "Please enter a password!")
            return

        # (بعداً اینجا فراخوانی crypto_engine.encrypt_file() انجام میشه)
        self.status.set(f"Encrypting {self.selected_file.get()} with {self.algorithm.get()}-{self.mode.get()}...")
        messagebox.showinfo("Encrypt", "Encryption started (simulation).")

    def decrypt_action(self):
        if not self.password.get():
            messagebox.showwarning("Warning", "Please enter a password!")
            return

        # (بعداً اینجا فراخوانی crypto_engine.decrypt_file() انجام میشه)
        self.status.set(f"Decrypting {self.selected_file.get()} with {self.algorithm.get()}-{self.mode.get()}...")
        messagebox.showinfo("Decrypt", "Decryption started (simulation).")


# فقط برای اجرا مستقیم
if __name__ == "__main__":
    app = App()
    app.mainloop()
