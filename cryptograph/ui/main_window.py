#from pydoc import plaintext

import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptograph.core.crypto import encrypt_bytes, decrypt_bytes
from cryptograph.utils.file_helpers import read_encrypted_file, read_plain_file, write_plain_file, write_encrypted_file


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

        encrypt_btn = ctk.CTkButton(button_frame, text="🔒 Encrypt", command=self.encrypt_action, width=120, fg_color="#1E90FF", hover_color="#63B8FF")
        encrypt_btn.grid(row=0, column=0, padx=20)

        decrypt_btn = ctk.CTkButton(button_frame, text="🔓 Decrypt", command=self.decrypt_action, width=120, fg_color="#32CD32", hover_color="#7CFC00")
        decrypt_btn.grid(row=0, column=1, padx=20)

        # ===== Status Bar =====
        status_label = ctk.CTkLabel(self, textvariable=self.status, text_color="gray", anchor="w")
        status_label.pack(fill="x", padx=20, pady=(40, 0))

    # ===== Event Functions =====

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select a file")
        if file_path:
            self.selected_file.set(file_path)
            self.status.set("File selected ✅")

    def encrypt_action(self):
        if not self.password.get() or self.selected_file.get() == "No file selected":
            messagebox.showwarning("Warning", "Please select a file and enter a password!")
            return

        try:
            input_path = self.selected_file.get()
            output_path = input_path + ".enc"
            plaintext = read_plain_file(input_path)
            header_bytes, cyphertext = encrypt_bytes(plaintext, self.password.get(), self.algorithm.get(), self.mode.get())
            write_encrypted_file(output_path, header_bytes, cyphertext)
            self.status.set(f"Encrypting {self.selected_file.get()} with {self.algorithm.get()}-{self.mode.get()}...")
            messagebox.showinfo("Encrypt", "Encryption Completed.")
        except Exception as e:
            self.status.set(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def decrypt_action(self):
        if not self.password.get() or self.selected_file.get() == "No file selected":
            messagebox.showwarning("Warning", "Please select a file and enter a password!")
            return

        try:
            input_path = self.selected_file.get()
            output_path = input_path[:-4] #remove .enc
            header_bytes, ciphertext = read_encrypted_file(input_path)
            plaintext = decrypt_bytes(header_bytes, ciphertext, self.password.get())
            write_plain_file(output_path, plaintext)
            self.status.set(f"Decrypting {self.selected_file.get()} with {self.algorithm.get()}-{self.mode.get()}...")
            messagebox.showinfo("Decrypt", "Decryption Completed.")
        except Exception as e:
            self.status.set(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))


# فقط برای اجرا مستقیم
if __name__ == "__main__":
    app = App()
    app.mainloop()
