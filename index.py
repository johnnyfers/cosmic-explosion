# python version: 3.9.6
import hashlib
import base64

# Function to generate a secret key from a passphrase
def generate_secret_key(passphrase):
    return hashlib.sha256(passphrase.encode()).digest()

# Function to encrypt a password
def encrypt_password(password, secret_key):
    encrypted_password = []
    for i in range(len(password)):
        key_c = secret_key[i % len(secret_key)]
        encrypted_password.append(chr((ord(password[i]) + key_c) % 256))
    return base64.urlsafe_b64encode("".join(encrypted_password).encode()).decode()

# Function to decrypt a password
def decrypt_password(encrypted_password, secret_key):
    decrypted_password = []
    encrypted_password = base64.urlsafe_b64decode(encrypted_password).decode()
    for i in range(len(encrypted_password)):
        key_c = secret_key[i % len(secret_key)]
        decrypted_password.append(chr((ord(encrypted_password[i]) - key_c) % 256))
    return "".join(decrypted_password)

# Main function to handle user input and execution
def main():
    operation = input("Select operation (encrypt or decrypt): ").lower()

    if operation == "encrypt":
        password = input("Enter the password to encrypt: ")
        passphrase = input("Enter the passphrase: ")
        secret_key = generate_secret_key(passphrase)
        encrypted_password = encrypt_password(password, secret_key)
        print("Encrypted password:", encrypted_password)

    elif operation == "decrypt":
        encrypted_password = input("Enter the encrypted password: ")
        passphrase = input("Enter the passphrase: ")
        secret_key = generate_secret_key(passphrase)
        decrypted_password = decrypt_password(encrypted_password, secret_key)
        print("Decrypted password:", decrypted_password)

    else:
        print("Invalid operation. Please select either 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
