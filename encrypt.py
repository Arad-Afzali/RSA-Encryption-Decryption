from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys

def encrypt_message(message):
    with open('keys/public_key.pem', 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())

    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    
    with open('encrypted_message.bin', 'wb') as enc_file:
        enc_file.write(encrypted_message)
    
    print("Message encrypted and saved.")
    return encrypted_message

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python encrypt.py <message>")
    else:
        encrypt_message(sys.argv[1])
