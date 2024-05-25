from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_message():
    with open('keys/private_key.pem', 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())

    with open('encrypted_message.bin', 'rb') as enc_file:
        encrypted_message = enc_file.read()

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    
    print("Decrypted message:", decrypted_message.decode())
    return decrypted_message.decode()

if __name__ == "__main__":
    decrypt_message()
