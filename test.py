import struct
import unittest
from unittest.mock import MagicMock

import Client
from Client import Connection, Message, CODE
from unittest.mock import patch, MagicMock

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib


def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ciphertext


def decrypt_aes(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()


class ClientTests(unittest.TestCase):

    # Headers for request
    # +--------------+------+--------+
    # |    Field     | size | symbol |
    # +--------------+------+--------+
    # | Version      |    1 | b      |
    # | Code         |    2 | H      |
    # | Payload size |    4 | I      |
    # +--------------+------+--------+

    @staticmethod
    def test_client_response_registration_success():
        conn = Connection()
        raw_data = struct.pack("<bHI16s", 24, 1600, 16, "64f3f63985f04beb81a0e43321880182".encode("utf-8"))
        conn.analyze_response(raw_data)
        # self.assertEqual(True, False)  # add assertion here

    def test_client_response_SYMMETRIC_KEY_SUCCESS(self):
        conn = Connection()
        # <bHI16s16sQ32sB16s16s8s16s32s8s
        data = struct.pack("<16sQ32s", "key-iv-8429".encode("utf-8"), 500, "key-i30vTG29aD".encode("utf-8"))
        enc_data = encrypt_aes(data, hashlib.sha256("mykey").hexdigest())

        raw_data = struct.pack("<bHI16s56sB16s16s8s16s32s8s", 24, Client.RESPONSE.SYMMETRIC_KEY_SUCCESS.value, 16,
                               "64f3f63985f04beb81a0e43321880182".encode("utf-8"),
                               #  iv                          Nonce     AES key
                               # enc_data
                               "key-iv-8429".encode("utf-8"), 500, "key-i30vTG29aD".encode("utf-8"),
                               24, "client id".encode("utf-8"), "server id".encode("utf-8"),
                               "16:42:50:40".encode("utf-8"),
                               "iv".encode("utf-8"),
                               "key for server".encode("utf-8"), "16:42:50:40".encode("utf-8"))
        conn.analyze_response(raw_data)

    @patch('Client.Connection.send_msg')
    def test_registration_request(self, mock_func: MagicMock):
        conn = Connection()
        mock_func.return_value = 20
        result = conn.register_with_auth_server("user123", "1239")

    @staticmethod
    def test_aes_key_request():
        conn = Connection()
        conn.request_aes_key()


class MessageTests(unittest.TestCase):

    def test_message_request_aes_key(self):
        pass
        # Message.request_aes_key("id-3fji10", 20, "127.0.0.1", 80)


if __name__ == '__main__':
    unittest.main()
