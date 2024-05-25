# RSA Encryption and Decryption Project

This project provides a graphical user interface (GUI) for encrypting and decrypting messages using RSA (Rivest-Shamir-Adleman) encryption. The application supports key generation, message encryption, and message decryption.

![alt text](<ss/ss.png>)

## Prerequisites

- Python 3.8 or higher
- `pip` (Python package installer)

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/Arad-Afzali/RSA-Encryption-Decryption.git
    cd RSA-Encryption-Decryption
    ```

2. **Create and activate a virtual environment** (recommended):
    
    **On macOS/Linux:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

    **On Windows:**
    ```cmd
    python3 -m venv venv
    venv\Scripts\activate
    ```

3. **Install the dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the main script**:
    ```bash
    python3 gui.py
    ```

2. **Using the GUI**:
    - **Generate Keys**: Use the 'Generate Keys' tab to create a new RSA(3072bits) key pair.
    - **Encrypt Message**: Enter the message to be encrypted and select the public key in the 'Encrypt' tab.
    - **Decrypt Message**: Enter the encrypted message and select the private key in the 'Decrypt' tab.

### Main Components

- **gui.py**: Defines the graphical user interface using `tkinter`.
- **generatekey.py**: Contains functions for generating secure RSA key pairs.
- **encrypt.py**: Provides functions to encrypt messages using RSA.
- **decrypt.py**: Provides functions to decrypt RSA-encrypted messages.

## Note on Key Management

When you generate keys, the private key is saved as `private_key.pem` and the public key as `public_key.pem` in the specified folder. It is crucial to save these keys securely, as the private key is required for decryption. If the private key is lost, encrypted messages cannot be decrypted, and their contents will be irretrievable.

### Warnings

- **Store the Private Key Securely**: Ensure that the private key file is stored in a secure location. Do not leave it in a publicly accessible or unprotected directory.
- **Backup the Private Key**: Make backups of the private key file in case of accidental deletion or hardware failure.
- **Do Not Share the Private Key**: Do not share the private key file with unauthorized individuals. Anyone with access to the private key can decrypt corresponding messages.
- **Encryption Safety**: Be aware that if the private key file is compromised, the security of the encrypted messages is also compromised.
- **Manual Key Management**: The text encryption keys are not saved anywhere else by the application. Users must manually save these keys and ensure their security. If the key is lost, the encrypted text cannot be decrypted.

## Dependencies

The project requires the following Python packages, listed in `requirements.txt`:

```plaintext
pycryptodome==3.20.0
tk==0.1.0
```

## Notes

- Ensure you have the necessary permissions to execute scripts on your operating system.
- This project uses the `pycryptodome` library for cryptographic functions.
- If you encounter any issues, please open an issue on GitHub.
