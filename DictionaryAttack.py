# Q2: Dictionary attack script

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
from Crypto.Util.Padding import pad


def encrypt_aes(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext


def get_nonce():
    # simulate reading the nonce value from packet
    return b'\xccW\xceWE\xe1\xa4\x93'


def get_encrypted_nonce():
    # simulate reading the encrypted nonce packet
    return b'\x83Xb%0\n\xcd!-V\xca\x04l\x8bC;'


def get_iv():
    # simulate reading the iv value from packet
    return b'\xdbw\xab\xfb\xc7\xc7\x9a\xe6\xc2h\x96\x91\xc8a\xd9\x1a'


class PasswordDict:
    lines = []
    hashed_passwords = []

    def __init__(self):
        if not os.path.exists("hashedPasswords"):
            print("No hash table found!, exiting")
            exit(1)
        else:
            with open("hashedPasswords", 'r') as file:
                file_content = file.read()
                self.lines = [passwordRow.strip() for passwordRow in file_content.split('\n') if passwordRow]
                self._hashed_passwords()

    def _hashed_passwords(self):
        for line in self.lines:
            password = line[:line.find(":")]
            hash = line[line.find(":") + 1:]
            self.hashed_passwords.append((password, hash))
        return self.hashed_passwords


class DictionaryAttack:
    password_dict = PasswordDict()
    client_nonce = get_nonce()
    iv = get_iv()
    encrypted_nonce = get_encrypted_nonce()

    def encrypt_and_compare(self):
        for pass_tuple in self.password_dict.hashed_passwords:
            attempted_encrypted_nonce = encrypt_aes(self.client_nonce, bytes.fromhex(pass_tuple[1]), self.iv)
            if attempted_encrypted_nonce == self.encrypted_nonce:
                print(f"Found the password! the password is: {pass_tuple[0]}")
                return

        print(f"the password is not found in this dictionary")


if __name__ == '__main__':
    DictionaryAttack().encrypt_and_compare()
