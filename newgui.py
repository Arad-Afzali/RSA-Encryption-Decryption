import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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
        ttk.Button(tab, text="Generate Keys", command=self.generate_keys).pack(pady=10)
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

    def generate_keys(self):
        if hasattr(self, 'key_folder'):
            os.makedirs(self.key_folder, exist_ok=True)
            key_path = os.path.join(self.key_folder, 'keys')
            os.makedirs(key_path, exist_ok=True)

            key = RSA.generate(4096)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            with open(os.path.join(key_path, 'private_key.pem'), 'wb') as priv_file:
                priv_file.write(private_key)

            with open(os.path.join(key_path, 'public_key.pem'), 'wb') as pub_file:
                pub_file.write(public_key)

            messagebox.showinfo("Success", "Keys generated and saved.")
        else:
            messagebox.showerror("Error", "Please choose a destination folder first.")

    def choose_public_key(self):
        self.public_key_path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM files", "*.pem")])
        if self.public_key_path:
            messagebox.showinfo("Selected", f"Public Key: {self.public_key_path}")

    def encrypt_message(self):
        message = self.encrypt_text.get("1.0", tk.END).strip()
        if hasattr(self, 'public_key_path') and message:
            with open(self.public_key_path, 'rb') as pub_file:
                public_key = RSA.import_key(pub_file.read())

            cipher = PKCS1_OAEP.new(public_key)
            encrypted_message = cipher.encrypt(message.encode())
            self.encrypted_output.delete("1.0", tk.END)
            self.encrypted_output.insert(tk.END, encrypted_message.hex())
        else:
            messagebox.showerror("Error", "Please select a public key and enter a message to encrypt.")

    def choose_private_key(self):
        self.private_key_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
        if self.private_key_path:
            messagebox.showinfo("Selected", f"Private Key: {self.private_key_path}")

    def decrypt_message(self):
        encrypted_message = bytes.fromhex(self.decrypt_text.get("1.0", tk.END).strip())
        if hasattr(self, 'private_key_path') and encrypted_message:
            with open(self.private_key_path, 'rb') as priv_file:
                private_key = RSA.import_key(priv_file.read())

            cipher = PKCS1_OAEP.new(private_key)
            decrypted_message = cipher.decrypt(encrypted_message)
            self.decrypted_output.delete("1.0", tk.END)
            self.decrypted_output.insert(tk.END, decrypted_message.decode())
        else:
            messagebox.showerror("Error", "Please select a private key and enter a message to decrypt.")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
