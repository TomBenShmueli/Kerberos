import hashlib
import os
import socket
import time
import uuid
from enum import Enum
from logging import Logger
import struct
from typing import Tuple

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

logger = Logger("")


def encrypt_aes(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext


def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data


def generate_iv():
    return get_random_bytes(16)  # 16 bytes for IV


def _is_socket_connected(s: socket.socket) -> bool:
    try:
        s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        return True
    except socket.error as e:
        print(e)
        return False


def generate_nonce(length):
    return get_random_bytes(length)


class CODE(Enum):
    CLIENT_REQUEST_REGISTER_AUTH_CODE = 1024
    CLIENT_REQUEST_AES_KEY_FOR_SERVER_MSG = 1027

    #     Message server
    ACKE_ACCEPTED_SYMMETRIC_KEY = 1604
    ACKE_ACCEPTED_MESSAGE = 1605
    GENERAL_ERROR_IN_SERVER = 1609


class RESPONSE(Enum):
    AUTH_SERVER_REGISTRATION_SUCCESS = 1600
    AUTH_SERVER_REGISTRATION_FAIL = 1601

    SYMMETRIC_KEY_SUCCESS = 1603


class Message:
    clientID: uuid.UUID
    version: int
    code: int
    payload_size: int
    payload: any

    def __init__(self, client_id: uuid.UUID, version: int, code: int, payload_size: int, payload):
        self.clientID = client_id
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.payload = payload

    def get_bytes(self):
        return struct.pack("<16sBHI", self.clientID.bytes, self.version, self.code,
                           self.payload_size) + self.payload

    @staticmethod
    def register_auth_server(version, username, password):
        # registering at auth server payload is 2 times 256
        # Todo notice this
        payload_size = 512

        username_with_null_char = username + "\\0"
        password_with_null_char = password + "\\0"
        # sets empty uuid for registration
        return Message(uuid.UUID(bytes=b'\x00' * 16), version, CODE.CLIENT_REQUEST_REGISTER_AUTH_CODE.value,
                       payload_size,
                       struct.pack("<255s255s", username_with_null_char.encode("ascii"),
                                   password_with_null_char.encode("ascii"))).get_bytes()

    @staticmethod
    def request_aes_key_from_auth(client_id, version, server_id, nonce):
        payload_size = 24
        return Message(client_id, version, CODE.CLIENT_REQUEST_AES_KEY_FOR_SERVER_MSG.value, payload_size,
                       struct.pack("<16s8s", server_id.bytes, nonce)).get_bytes()

    @staticmethod
    def send_aes_key_to_msg_server(key, ticket, iv, version: int, client_id: uuid.UUID, server_id: uuid.UUID):
        def create_authenticator():
            encrypt_version = encrypt_aes(int.to_bytes(version, 1, "little"), key, iv)
            encrypt_client_id = encrypt_aes(client_id.bytes, key, iv)
            encrypt_server_id = encrypt_aes(server_id.bytes, key, iv)

            current_timestamp = int(time.time())
            encrypt_creation_time = encrypt_aes(int.to_bytes(current_timestamp, 8, "little"), key, iv)

            return struct.pack("<16s16s32s32s16s", iv, encrypt_version, encrypt_client_id, encrypt_server_id,
                               encrypt_creation_time)

        return create_authenticator() + ticket


class Client:
    # Todo check that the time is correct
    # Todo check that the nonce is correct
    # Todo check input in general

    version = 24

    auth_server_address: str
    auth_server_port: int

    message_server_address: str
    message_server_port: int

    socket: socket = None
    is_connected: bool = False
    registration_waiting: bool = True
    key_request_waiting: bool = True

    username: str
    password: str = ""
    client_id: uuid.UUID

    # as we understood from questions in the forum if we have only 1 msg server then there is no need for
    # a server id therefor an empty id is put in
    server_id: uuid.UUID = uuid.UUID(bytes=b'\x00' * 16)

    nonce: bytes

    symmetric_key_for_msg_server: bytes
    ticket: Tuple

    def __init__(self):
        self.read_servers_info()
        self.read_client_info()

    def register_with_auth_server(self, username, password):
        msg_bytes = Message.register_auth_server(self.version, username, password)
        return self.send_msg(msg_bytes)

    def get_login_details_from_user(self):
        self.username = input("Enter Username:")
        while len(self.username) > 255:
            self.username = input("Too long of a Username, Enter Username:")

        password = input("Enter Password:")
        while len(password) > 255:
            password = input("Too long of a password, Enter password:")

        self.password = password

    def request_aes_key(self):
        self.nonce = generate_nonce(8)
        return self.send_msg(
            Message.request_aes_key_from_auth(self.client_id, self.version, self.server_id, self.nonce))

    def check_connection(self):
        self.is_connected = _is_socket_connected(self.socket)

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = sock
        sock.connect((self.auth_server_address, self.auth_server_port))
        self.check_connection()

        # asks user for login details if not registered
        if not os.path.exists("me.info"):
            self.get_login_details_from_user()
            # First login Register at auth server
            self.register_with_auth_server(self.username, self.password)

            # endless loop of listening till server response to registration
            while self.registration_waiting:
                if self.is_connected:
                    client.recv_messages()
                else:
                    time.sleep(0.1)

        # get the users password again
        else:
            self.password = input("Enter Password:")

        if self.request_aes_key() > 0:
            print("Key request sent to server...")
            time.sleep(0.5)
            while self.key_request_waiting:
                if self.is_connected:
                    client.recv_messages()
                else:
                    time.sleep(0.1)

            # closes connection with auth server.
            sock.close()
            # start connection to msg server.
            self.connect_to_msg_server()

    def read_servers_info(self) -> bool:
        if not os.path.exists("srv.info"):
            logger.error("srv info not exists")
            return False
        else:
            # reads the server's info from srv.info file
            with open("srv.info", "r") as srv_file:
                auth_server_data = srv_file.readline()
                message_server_data = srv_file.readline()

                colon_index_auth = auth_server_data.find(":")
                self.auth_server_address = auth_server_data[:colon_index_auth]
                self.auth_server_port = int(auth_server_data[colon_index_auth + 1:].replace("\n", ""))

                self.message_server_address = message_server_data[:colon_index_auth]
                self.message_server_port = int(message_server_data[colon_index_auth + 1:].replace("\n", ""))

            # return True

    def read_client_info(self) -> bool:
        if not os.path.exists("me.info"):
            logger.error("me info doesn't exists")
            return False
        else:
            with open("me.info", "r") as me_file:
                self.username = me_file.readline()
                self.client_id = uuid.UUID(me_file.readline())

    def recv_messages(self):
        if not self.is_connected:
            time.sleep(0.01)

        try:
            raw_data = self.socket.recv(4096)
            if raw_data:
                print(raw_data)
                self.analyze_response(raw_data)
        except ConnectionResetError as e:
            logger.info("{}".format(e))
        except ConnectionAbortedError as e:
            logger.info("connection was aborted by the software in your host machine")

    def send_msg(self, msg: str) -> int:
        if len(msg) < 4095:
            logger.info("Error: message is too big")
            try:
                return self.socket.send(msg)
            except Exception as e:
                print(e)
                logger.error('Action failed with exception ' + str(e))

    def disconnect(self):
        self.socket.close()
        self.is_connected = False

    def analyze_response(self, raw_data):
        headers_size = 7
        ticket_size = 103
        aes_key_index = 3
        response_code_index = 1

        client_id_index = 0
        iv_index = 1

        response_header = struct.unpack("<BHI", raw_data[:headers_size])
        response_code = response_header[response_code_index]

        if response_code == RESPONSE.AUTH_SERVER_REGISTRATION_SUCCESS.value:
            payload = struct.unpack("<16s", raw_data[headers_size:])
            client_uuid = uuid.UUID(bytes=payload[client_id_index])
            data = str(client_uuid)
            # saves client id to file
            with open("me.info", "w") as me_file:
                me_file.writelines([self.username, "\n", data])
                me_file.flush()
                self.client_id = client_uuid
            self.registration_waiting = False

        if response_code == RESPONSE.AUTH_SERVER_REGISTRATION_FAIL.value:
            logger.error("Registration failed")

        if response_code == RESPONSE.SYMMETRIC_KEY_SUCCESS.value:
            # unpacks the response from server
            payload = struct.unpack("<16s16s16s48sB16s16sQ16s48s24s", raw_data[headers_size:])
            iv = payload[iv_index]

            # gets the password hash to open the encryption
            key = SHA256.new(self.password.encode()).digest()

            self.symmetric_key_for_msg_server = decrypt_aes(payload[aes_key_index], key, iv)
            self.ticket = raw_data[ticket_size:]
            # self.ticket = struct.unpack("<B16s16sQ16s48s24s", raw_data[ticket_size:])

            # Todo check nonce match the nonce that client sent.

            self.key_request_waiting = False

    def connect_to_msg_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = sock
        sock.connect((self.message_server_address, self.message_server_port))
        self.check_connection()

        print(f"symmetric key with server msg: {self.symmetric_key_for_msg_server}")

        authenticator_iv = generate_iv()
        msg = Message.send_aes_key_to_msg_server(self.symmetric_key_for_msg_server, self.ticket, authenticator_iv,
                                                 self.version, self.client_id,
                                                 self.server_id)
        self.socket.send(msg)


if __name__ == '__main__':
    client = Client()
    client.start()
