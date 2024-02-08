import struct
import unittest
from unittest.mock import MagicMock

import Client
from Client import Client, Message, CODE
from unittest.mock import patch, MagicMock

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib


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
        conn = Client()
        raw_data = struct.pack("<bHI16s", 24, 1600, 16, "64f3f63985f04beb81a0e43321880182".encode("utf-8"))
        conn.analyze_response(raw_data)
        # self.assertEqual(True, False)  # add assertion here

    def test_client_response_SYMMETRIC_KEY_SUCCESS(self):
        conn = Client()

        with patch.object(conn, "password", new="123"):
            # <bHI16s16sQ32sB16s16s8s16s32s8s
            # data = struct.pack("<Q32s", 500, "key-i30vTG29aD".encode("utf-8"))

            key = Client.derive_key("123")

            enc_data1 = Client.encrypt_aes(str(10000), key)
            enc_data2 = Client.encrypt_aes("key-i30vTG29aD", key)
            # print(len("05005005005005005005005005005005"))
            print(len(enc_data1), len(enc_data2))

            data = struct.pack("<160s32s", enc_data1, enc_data2)

            raw_data = struct.pack("<bHI16s56sB16s16s8s16s32s8s", 24, Client.RESPONSE.SYMMETRIC_KEY_SUCCESS.value, 16,
                                   "64f3f63985f04beb81a0e43321880182".encode("utf-8"),

                                   #  iv                          Nonce     AES key
                                   data,
                                   # "key-iv-8429".encode("utf-8"), 500, "key-i30vTG29aD".encode("utf-8"),
                                   24, "client id".encode("utf-8"), "server id".encode("utf-8"),
                                   "16:42:50:40".encode("utf-8"),
                                   "iv".encode("utf-8"),
                                   "key for server".encode("utf-8"), "16:42:50:40".encode("utf-8"))
            conn.analyze_response(raw_data)

    @patch('Client.Connection.send_msg')
    def test_registration_request(self, mock_func: MagicMock):
        conn = Client()
        mock_func.return_value = 20
        result = conn.register_with_auth_server("user123", "1239")
        self.assertEqual(result, 20)

    @staticmethod
    def test_aes_key_request():
        conn = Client()
        with patch.object(conn, "client_id", new="Ok"):
            patch.object(conn, "VERSION", new=24)
            patch.object(conn, "message_server_address", new="127.0.0.1")
            patch.object(conn, "nonce", new=50)
            result = conn.request_aes_key()
            print(result)


class MessageTests(unittest.TestCase):

    def test_message_request_aes_key(self):
        pass
        # Message.request_aes_key("id-3fji10", 20, "127.0.0.1", 80)


if __name__ == '__main__':
    unittest.main()
