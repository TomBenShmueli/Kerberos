import os
import socket
import time
from enum import Enum
from logging import Logger
import struct

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

logger = Logger("")


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
    clientID: str
    version: int
    code: int
    payload_size: int
    payload: any

    def __init__(self, client_id: str, version: int, code: int, payload_size: int, payload):
        self.clientID = client_id
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.payload = payload

    def get_bytes(self):
        return struct.pack("<16sbHI", self.clientID.encode("ascii"), self.version, self.code,
                           self.payload_size) + self.payload

    @staticmethod
    def register_auth_server(version, username, password):
        # registering at auth server payload is 2 times 256
        payload_size = 512

        username_with_null_char = username + "\\0"
        password_with_null_char = password + "\\0"

        return Message("", version, CODE.CLIENT_REQUEST_REGISTER_AUTH_CODE.value, payload_size,
                       struct.pack("<255s255s", username_with_null_char.encode("ascii"),
                                   password_with_null_char.encode("ascii"))).get_bytes()

    @staticmethod
    def request_aes_key(client_id, version, message_server_address, nonce):
        payload_size = 24
        return Message(client_id, version, CODE.CLIENT_REQUEST_AES_KEY_FOR_SERVER_MSG.value, payload_size,
                       struct.pack("<16s8s", message_server_address.encode("ascii"), nonce)).get_bytes()


class Connection:
    auth_server_address = "127.0.0.1"
    auth_server_port = 1256

    message_server_address = "127.0.0.1"
    message_server_port = 1256
    VERSION = 24

    socket: socket = None
    is_connected: bool = False

    username: str
    client_id: str
    nonce: bytes

    def __init__(self):
        self.read_servers_info()
        self.read_client_info()

    def register_with_auth_server(self, username, password):
        msg_bytes = Message.register_auth_server(self.VERSION, username, password)
        bytes_sent = self.send_msg(msg_bytes)
        print("bytes sent {}", bytes_sent)

    def get_login_details_from_user(self):
        self.username = input("Enter Username:")
        while len(self.username) > 255:
            self.username = input("Too long of a Username, Enter Username:")

        password = input("Enter Password:")
        while len(password) > 255:
            password = input("Too long of a password, Enter password:")

        # First login Register at auth server
        self.register_with_auth_server(self.username, password)

    def request_aes_key(self):
        self.nonce = generate_nonce(8)
        print(Message.request_aes_key(self.client_id, self.VERSION, self.message_server_address, self.nonce))

    def check_connection(self):
        self.is_connected = _is_socket_connected(self.socket)

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = sock
        sock.connect((self.auth_server_address, self.auth_server_port))
        self.check_connection()

        # asks user for login details if not registered
        # if not os.path.exists("me.info"):
        self.get_login_details_from_user()

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

            return True

    def read_client_info(self) -> bool:
        if not os.path.exists("me.info"):
            logger.error("me info doesn't exists")
            return False
        else:
            with open("me.info", "r") as me_file:
                self.username = me_file.readline()
                self.client_id = me_file.readline()

    def recv_messages(self):
        if not self.is_connected:
            time.sleep(0.01)

        try:
            raw_data = self.socket.recv(4096)
            if raw_data:
                print(raw_data)
                self.analyze_response(raw_data)
            else:
                pass
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
                raise Exception("Could not have sent Message")

    def disconnect(self):
        self.socket.close()
        self.is_connected = False

    def analyze_response(self, raw_data):
        response_header = struct.unpack("<bHI", raw_data[:7])
        response_code = response_header[1]
        response_payload_size = response_header[2]

        if response_code == RESPONSE.AUTH_SERVER_REGISTRATION_SUCCESS.value:
            payload = struct.unpack("16s", raw_data[7:])
            data = payload[0].decode("ascii")
            with open("me.info", "w") as me_file:
                me_file.writelines([self.username, "\n", data])
                self.client_id = data

        if response_code == RESPONSE.AUTH_SERVER_REGISTRATION_FAIL.value:
            logger.error("Registration failed")

        if response_code == RESPONSE.SYMMETRIC_KEY_SUCCESS.value:
            # client id of 16 bytes
            # 56 bytes of encrypted key
            # 97 bytes of ticket

            payload = struct.unpack("<16s56s97s", raw_data[7:])
            pass


if __name__ == '__main__':
    connection = Connection()
    connection.connect()
