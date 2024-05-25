from Crypto.PublicKey import RSA
import os

def generate_keys():
    os.makedirs('keys', exist_ok=True)  # Ensure the 'keys' directory exists

    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open('keys/private_key.pem', 'wb') as priv_file:
        priv_file.write(private_key)

    with open('keys/public_key.pem', 'wb') as pub_file:
        pub_file.write(public_key)

    print("Keys generated and saved.")

if __name__ == "__main__":
    generate_keys()