import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
from generatekey import generate_keys
from encrypt import encrypt_message
from decrypt import decrypt_message

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption/Decryption App")
        self.create_tabs()

    def create_tabs(self):
        tab_control = ttk.Notebook(self.root)

        tab1 = ttk.Frame(tab_control)
        tab_control.add(tab1, text='Generate Keys')
        self.create_generate_keys_tab(tab1)

        tab2 = ttk.Frame(tab_control)
        tab_control.add(tab2, text='Encrypt')
        self.create_encrypt_tab(tab2)

        tab3 = ttk.Frame(tab_control)
        tab_control.add(tab3, text='Decrypt')
        self.create_decrypt_tab(tab3)

        tab_control.pack(expand=1, fill="both")

    def create_generate_keys_tab(self, tab):
        ttk.Label(tab, text="Generate RSA Keys").pack(pady=10)
        ttk.Button(tab, text="Generate Keys", command=self.generate_keys_thread).pack(pady=10)
        self.key_folder_label = ttk.Label(tab, text="No folder selected")
        self.key_folder_label.pack(pady=10)
        ttk.Button(tab, text="Choose Destination Folder", command=self.choose_key_folder).pack(pady=10)

    def create_encrypt_tab(self, tab):
        ttk.Label(tab, text="Input Text to Encrypt").pack(pady=10)
        self.encrypt_text = tk.Text(tab, height=10, width=50)
        self.encrypt_text.pack(pady=10)
        ttk.Button(tab, text="Choose Public Key", command=self.choose_public_key).pack(pady=10)
        ttk.Button(tab, text="Encrypt", command=self.encrypt_message).pack(pady=10)
        self.encrypted_output = tk.Text(tab, height=10, width=50)
        self.encrypted_output.pack(pady=10)

    def create_decrypt_tab(self, tab):
        ttk.Label(tab, text="Input Encrypted Text").pack(pady=10)
        self.decrypt_text = tk.Text(tab, height=10, width=50)
        self.decrypt_text.pack(pady=10)
        ttk.Button(tab, text="Choose Private Key", command=self.choose_private_key).pack(pady=10)
        ttk.Button(tab, text="Decrypt", command=self.decrypt_message).pack(pady=10)
        self.decrypted_output = tk.Text(tab, height=10, width=50)
        self.decrypted_output.pack(pady=10)

    def choose_key_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.key_folder = folder
            self.key_folder_label.config(text=self.key_folder)

    def generate_keys_thread(self):
        thread = threading.Thread(target=self.generate_keys)
        thread.start()

    def generate_keys(self):
        if hasattr(self, 'key_folder'):
            try:
                generate_keys(self.key_folder)
                self.show_message("Success", "Keys generated and saved.")
            except Exception as e:
                self.show_message("Error", f"Failed to generate keys: {e}")
        else:
            self.show_message("Error", "Please choose a destination folder first.")

    def show_message(self, title, message):
        # Ensure that message box is called from the main thread
        self.root.after(0, lambda: messagebox.showinfo(title, message))

    def choose_public_key(self):
        self.public_key_path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM files", "*.pem")])
        if self.public_key_path:
            messagebox.showinfo("Selected", f"Public Key: {self.public_key_path}")

    def encrypt_message(self):
        message = self.encrypt_text.get("1.0", tk.END).strip()
        if hasattr(self, 'public_key_path') and message:
            try:
                encrypted_message = encrypt_message(message, self.public_key_path)
                self.encrypted_output.delete("1.0", tk.END)
                self.encrypted_output.insert(tk.END, encrypted_message.hex())
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        else:
            messagebox.showerror("Error", "Please select a public key and enter a message to encrypt.")

    def choose_private_key(self):
        self.private_key_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
        if self.private_key_path:
            messagebox.showinfo("Selected", f"Private Key: {self.private_key_path}")

    def decrypt_message(self):
        encrypted_message = bytes.fromhex(self.decrypt_text.get("1.0", tk.END).strip())
        if hasattr(self, 'private_key_path') and encrypted_message:
            try:
                decrypted_message = decrypt_message(encrypted_message, self.private_key_path)
                self.decrypted_output.delete("1.0", tk.END)
                self.decrypted_output.insert(tk.END, decrypted_message)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        else:
            messagebox.showerror("Error", "Please select a private key and enter a message to decrypt.")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
