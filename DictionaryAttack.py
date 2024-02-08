# Q2: Dictionary attack script

# From Wikipedia:
# In cryptanalysis and computer security, a dictionary attack is an attack using a restricted subset of a keyspace
# to defeat a cipher or authentication mechanism by trying to determine its decryption key or passphrase,
# sometimes trying thousands or millions of likely possibilities often obtained from lists of past security breaches.

# In this script, we will attempt to steal the AES symmetrical key
# Step 1: Create a dictionary of common password variations
# Step 2: Save the password hash received from the server as source(Commonly taken from data leaks containing pw hashes)
# Step 3: Save the NONCE sent to the server by the client
# Step 4: Save the encrypted NONCE sent by the server to the client
# Step 4: Use the dictionary, and hash the passwords.
# Step 5: Encrypt the client NONCE with the hashed passwords. and compare to the NONCE sent by the server,
# a match will indicate that we cracked the password!

import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from logging import Logger
from Crypto.Util.Padding import pad

logger = Logger("")


class PasswordDict:
    passwords = []
    hashed_passwords = []

    def __init__(self):
        if not os.path.exists("passwords"):
            logger.error(f"password file doesn't exist")
        else:
            with open("passwords", 'r') as file:
                file_content = file.read()
                self.passwords = [passwordRow.strip() for passwordRow in file_content.split('\n') if passwordRow]

    def hashed_passwords(self):
        for password in self.passwords:
            self.hashed_passwords.append(SHA256.new(password.encode()).hexdigest())
        return self.hashed_passwords


class DictionaryAttack:
    password_dict = PasswordDict()
    client_nonce = -1
    server_nonce = -1
    iv = -1

    def __init__(self, client_nonce, server_nonce, iv):
        self.client_nonce = client_nonce
        self.server_nonce = server_nonce
        self.iv = iv

    def encrypt_aes(self, data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return ciphertext

    def encrypt_and_compare(self):
        for hashed_password in self.password_dict.hashed_passwords():
            attempted_encrypted_nonce = self.encrypt_aes(self.client_nonce, hashed_password, self.iv)
            if attempted_encrypted_nonce == self.server_nonce:
                return True
        return False










