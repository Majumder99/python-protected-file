import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt_file(filename, password):
    """Encrypts a file using a password.

    Args:
        filename: The path to the file to encrypt.
        password: The password to use for encryption.

    Returns:
        The path to the encrypted file.
    """

    # Generate a salt for the KDF
    salt = os.urandom(16)

    # Generate a Fernet key from the password using a KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    print(password)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Generate a Fernet object from the key
    fernet = Fernet(key)

    # Read the contents of the file
    with open(filename, "rb") as f:
        file_data = f.read()

    # Encrypt the file data
    encrypted_data = fernet.encrypt(file_data)

    # Write the encrypted file to disk
    encrypted_filename = os.path.join(os.path.dirname(filename), "encrypted_" + os.path.basename(filename))
    with open(encrypted_filename, "wb") as f:
        f.write(encrypted_data)

    return encrypted_filename

def decrypt_file(filename, password):
    """Decrypts a file using a password.

    Args:
        filename: The path to the encrypted file.
        password: The password to use for decryption.

    Returns:
        The path to the decrypted file.
    """

    # Generate a salt for the KDF
    salt = os.urandom(16)

    # Generate a Fernet key from the password using a KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    print(password)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Generate a Fernet object from the key
    fernet = Fernet(key)

    # Read the contents of the encrypted file
    with open(filename, "rb") as f:
        encrypted_data = f.read()

    # Decrypt the file data
    decrypted_data = fernet.decrypt(encrypted_data)

    # Write the decrypted file to disk
    decrypted_filename = os.path.join(os.path.dirname(filename), "decrypted_" + os.path.basename(filename))
    with open(decrypted_filename, "wb") as f:
        f.write(decrypted_data)

    return decrypted_filename

if __name__ == "__main__":
    # Get the file to encrypt
    filename = input("Enter the path to the file to encrypt: ")

    # Get the password to encrypt the file with
    password = input("Enter the password to encrypt the file with: ")

    # Encrypt the file
    encrypted_filename = encrypt_file(filename, password)

    # Print the path to the encrypted file
    print("The encrypted file has been saved to:", encrypted_filename)

    # Get the path to the encrypted file to decrypt
    encrypted_filename = input("Enter the path to the encrypted file to decrypt: ")

    # Get the password to decrypt the file with
    password = input("Enter the password to decrypt the file with: ")

    # Decrypt the file
    decrypted_filename = decrypt_file(encrypted_filename, password)

    # Print the path to the decrypted file
    print("The decrypted file has been saved to:", decrypted_filename)
