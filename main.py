#Importing all the needed libraries for the PW Manager
import json, hashlib, getpass, os, pyperclip, sys
from cryptography.fernet import Fernet

# Below is a function to hash the master password
def hash_password(password):

    sha512 = hashlib.sha512()
    sha512.update(password.encode())

    return sha512.hexdigest()

