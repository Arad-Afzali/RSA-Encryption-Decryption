from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_message(message, public_key_path):
    with open(public_key_path, 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())

    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    
    return encrypted_message

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python encrypt.py <message> <public_key_path>")
    else:
        encrypted_message = encrypt_message(sys.argv[1], sys.argv[2])
        with open('encrypted_message.bin', 'wb') as enc_file:
            enc_file.write(encrypted_message)
        print("Message encrypted and saved.")
