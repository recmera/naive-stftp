#!/usr/bin/env python

from cryptography.fernet import Fernet


# Encode the message
# message = "secret"
# encoded = message.encode()

# Encrypt the message
def encrypt(encoded):

    # Get the key from the file
    file = open("key.key", 'rb')
    key = file.read()
    file.close()

    f = Fernet(key)
    encrypted = f.encrypt(encoded)
    return encrypted

# Decrypt the encrypted message
def decrypt(encrypted):

    # Get the key from the file
    file = open("key.key", 'rb')
    key = file.read()
    file.close()
    
    f2 = Fernet(key)
    decrypted = f2.decrypt(encrypted)
    return decrypted
