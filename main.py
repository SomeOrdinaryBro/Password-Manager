# Importing all the needed libraries
import json           # for handling JSON data
import hashlib        # for cryptographic hash functions
import getpass        # for secure password input
import os             # for operating system functions
import pyperclip      # for clipboard operations
import sys            # for system-specific parameters and functions

from cryptography.fernet import Fernet  # Fernet is a symmetric encryption algorithm included in the cryptography library

def hash_pw(password):
    """
    Function to hash the master password using SHA-512 algorithm.

    Parameters:
    password (str): The master password to be hashed.

    Returns:
    str: The hashed password.
    """
    sha512 = hashlib.sha512()    # Creating a SHA-512 hash object
    sha512.update(password.encode())  # Updating the hash object with the encoded password
    return sha512.hexdigest()     # Returning the hexadecimal digest of the hash

def gen_key():
    """
    Function to generate a key for encryption using Fernet.

    Returns:
    bytes: The generated key.
    """
    return Fernet.gen_key()   # Generating a key for Fernet encryption

def initialize_cipher(key):
    """
    Function to initialize a Fernet cipher with the given key.

    Parameters:
    key (bytes): The key for Fernet encryption.

    Returns:
    cryptography.fernet.Fernet: A Fernet cipher object.
    """
    return Fernet(key)   # Initializing a Fernet cipher with the provided key

def encrypt_pw(cipher, password):
    """
    Function to encrypt a password using the provided Fernet cipher.

    Parameters:
    cipher (cryptography.fernet.Fernet): The Fernet cipher object.
    password (str): The password to encrypt.

    Returns:
    str: The encrypted password.
    """
    return cipher.encrypt(password.encode()).decode()  # Encrypting the password and decoding it to a string

def decrypt_pw(cipher, encrypted_pw):
    """
    Function to decrypt an encrypted password using the provided Fernet cipher.

    Parameters:
    cipher (cryptography.fernet.Fernet): The Fernet cipher object.
    encrypted_pw (str): The encrypted password to decrypt.

    Returns:
    str: The decrypted password.
    """
    return cipher.decrypt(encrypted_pw.encode()).decode()  # Decrypting the password and decoding it to a string

def register(username, master_password):
    """
    Registers a new user by storing their username and hashed master password in a JSON file.

    Parameters:
    username (str): The username of the new user.
    master_password (str): The master password of the new user.

    Returns:
    None
    """
    hashed_master_password = hash_password(master_password)  # Hashing the master password
    user_data = {'username': username, 'master_password': hashed_master_password}  # Creating a dictionary with username and hashed master password
    file_name = 'user_data.json'  # Setting the file name for storing user data

    # Checking if the user data file exists and is empty
    if os.path.exists(file_name) and os.path.getsize(filename) == 0:
        with open(file_name, 'w') as file:
            json.dump(user_data, file)  # Writing user data to the JSON file
            print("\n[+] Registration complete!!\n")  # Printing registration success message
    else:
        with open(file_name, 'x') as file:  # If the file does not exist or is not empty, create a new file
            json.dump(user_data, file)  # Writing user data to the JSON file
            print("\n[+] Registration complete!!\n")  # Printing registration success message
