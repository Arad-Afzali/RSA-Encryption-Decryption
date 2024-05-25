import tkinter as tk
from tkinter import messagebox
from generatekey import generate_keys as gen_keys
from encrypt import encrypt_message
from decrypt import decrypt_message

class CryptoApp:
    def __init__(self, root):
        self.root = root
        root.title("Crypto GUI")

        self.label = tk.Label(root, text="Enter text to encrypt:")
        self.label.pack()

        self.text_entry = tk.Entry(root, width=50)
        self.text_entry.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_text)
        self.decrypt_button.pack()

        self.generate_button = tk.Button(root, text="Generate Keys", command=self.generate_keys)
        self.generate_button.pack()

        self.output_label = tk.Label(root, text="Output:")
        self.output_label.pack()

        self.output_text = tk.Text(root, height=10, width=50)
        self.output_text.pack()

    def generate_keys(self):
        gen_keys()
        messagebox.showinfo("Info", "Keys generated and saved.")

    def encrypt_text(self):
        message = self.text_entry.get()
        if not message:
            messagebox.showwarning("Warning", "Please enter text to encrypt.")
            return
        encrypted_message = encrypt_message(message)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, encrypted_message)
        messagebox.showinfo("Info", "Message encrypted and saved.")

    def decrypt_text(self):
        decrypted_message = decrypt_message()
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, decrypted_message)
        messagebox.showinfo("Info", "Message decrypted and displayed.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
