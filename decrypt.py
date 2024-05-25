from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_message(encrypted_message, private_key_path):
    with open(private_key_path, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    
    # Overwrite and delete sensitive data
    encrypted_message = b'\x00' * len(encrypted_message)
    private_key = b'\x00' * len(private_key.export_key())
    del encrypted_message, private_key, cipher

    return decrypted_message.decode()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python decrypt.py <encrypted_message_path> <private_key_path>")
    else:
        with open(sys.argv[1], 'rb') as enc_file:
            encrypted_message = enc_file.read()
        decrypted_message = decrypt_message(encrypted_message, sys.argv[2])
        print("Decrypted message:", decrypted_message)
