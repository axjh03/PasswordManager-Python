import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def create_master_password():
    password = input("Enter a master password: ")
    password = bytes(password, 'utf-8')
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_data(key, data):
    cipher = Fernet(key)
    cipher_text = cipher.encrypt(bytes(json.dumps(data), 'utf-8'))
    cipher_text = base64.b64encode(cipher_text)
    return cipher_text

def decrypt_data(key, data):
    cipher_text = base64.b64decode(data)
    cipher = Fernet(key)
    plain_text = json.loads(cipher.decrypt(cipher_text).decode())
    return plain_text

def save_data(data):
    with open('password_manager.json', 'wb') as file:
        file.write(data)

def load_data():
    with open('password_manager.json', 'rb') as file:
        data = file.read()
    return data

def add_password(key):
    website = input("Enter website name: ")
    username = input("Enter username: ")
    email = input("Enter email: ")
    password = input("Enter password: ")
    data = {
        website: {
            'username': username,
            'email': email,
            'password': password
        }
    }
    data = encrypt_data(key, data)
    save_data(data)
    print("Password added successfully.")

def search_password(key):
    website = input("Enter website name to search: ")
    data = load_data()
    data = decrypt_data(key, data)
    if website in data:
        print(data[website])
    else:
        print("Website not found.")

def main():
    key = create_master_password()
    while True:
        print("1. Add password")
        print("2. Search password")
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            add_password(key)
        elif choice == '2':
            search_password(key)
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

if __name__ == '__main__':
    main()
