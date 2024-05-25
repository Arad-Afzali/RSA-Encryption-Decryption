from Crypto.PublicKey import RSA
import os

def generate_keys(folder):
    os.makedirs(folder, exist_ok=True)
    key = RSA.generate(3072)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(os.path.join(folder, 'private_key.pem'), 'wb') as priv_file:
        priv_file.write(private_key)

    with open(os.path.join(folder, 'public_key.pem'), 'wb') as pub_file:
        pub_file.write(public_key)

    print("Keys generated and saved.")

if __name__ == "__main__":
    generate_keys('keys')
