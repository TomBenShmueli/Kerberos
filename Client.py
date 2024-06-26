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

    CLIENT_SENDING_KEY_TO_SERVER_MSG = 1028
    CLIENT_SENDING_MSG_TO_SERVER_MSG = 1029

    #     Message server
    MSG_SERVER_ACCEPTED_SYMMETRIC_KEY = 1604
    MSG_SERVER_ACCEPTED_MESSAGE = 1605
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
        """
        turns the class into packed bytes
        :return: returns the whole message packed to bytes with header & payload
        """
        return struct.pack("<16sBHI", self.clientID.bytes, self.version, self.code,
                           self.payload_size) + self.payload

    @staticmethod
    def register_auth_server(version, username, password):
        # registering at auth server payload is 2 times 256
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
    def send_aes_key_to_msg_server(key, ticket, version: int, client_id: uuid.UUID, server_id: uuid.UUID, request_code):
        def create_authenticator():
            authenticator_iv = generate_iv()
            encrypt_version = encrypt_aes(int.to_bytes(version, 1, "little"), key, authenticator_iv)
            encrypt_client_id = encrypt_aes(client_id.bytes, key, authenticator_iv)
            encrypt_server_id = encrypt_aes(server_id.bytes, key, authenticator_iv)

            current_timestamp = int(time.time())
            encrypt_creation_time = encrypt_aes(int.to_bytes(current_timestamp, 8, "little"), key, authenticator_iv)

            return struct.pack("<16s16s32s32s16s", authenticator_iv, encrypt_version, encrypt_client_id,
                               encrypt_server_id,
                               encrypt_creation_time)

        payload = create_authenticator() + ticket
        return Message(client_id, version, request_code, len(payload), payload).get_bytes()

    @staticmethod
    def encrypted_message(client_id, version, code, message, key):
        def create_message():
            message_iv = generate_iv()
            encrypted_msg = encrypt_aes(message, key, message_iv)
            message_size = len(encrypted_msg)
            return struct.pack(f"<I16s{message_size}s", message_size, message_iv, encrypted_msg)

        msg = create_message()
        payload_size = len(msg)
        return Message(client_id, version, code, payload_size, msg).get_bytes()


class Client:
    # Todo check input in general
    # Todo check that it's multithreaded

    version = 24

    auth_server_address: str
    auth_server_port: int

    message_server_address: str
    message_server_port: int

    socket: socket = None
    is_connected: bool = False

    # busy listening variables to wait for a response
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

        if not os.path.exists("me.info"):
            self.request_registration_from_auth()
        # if no need to register get the users password again
        else:
            self.password = input("Enter Password:")

        # blocking function until server responds
        self.request_key_from_auth(sock)

        # start connection to msg server.
        self.connect_to_msg_server()

        self.get_user_msg()

    def request_registration_from_auth(self):
        # asks user for login details if not registered
        self.get_login_details_from_user()
        # First login Register at auth server
        self.register_with_auth_server(self.username, self.password)
        print("\nRegistration Request sent to server")
        # endless loop of listening till server response to registration
        while self.registration_waiting:
            if self.is_connected:
                self.recv_messages()
            else:
                time.sleep(0.1)

    def request_key_from_auth(self, sock):
        if self.request_aes_key() > 0:
            print("Key request sent to Auth server...")
            time.sleep(0.5)
            while self.key_request_waiting:
                if self.is_connected:
                    self.recv_messages()
                else:
                    time.sleep(0.1)

            # closes connection with auth server.
            sock.close()

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
            # to show the output before any print
            time.sleep(0.01)
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
                self.analyze_response(raw_data)
        except ConnectionResetError as e:
            logger.info("{}".format(e))
        except ConnectionAbortedError as e:
            logger.info(f"connection was aborted {e}")

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
        """
        analyze the data that is received and acts as an api gateway
        :param raw_data: the data that received
        """
        headers_size = 7
        ticket_size = 103
        nonce_index = 2
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
            payload = struct.unpack("<16s16s16s48sB16s16sQ16s48s16s", raw_data[headers_size:])
            iv = payload[iv_index]

            # gets the password hash to open the encryption
            key = SHA256.new(self.password.encode()).digest()

            try:
                self.symmetric_key_for_msg_server = decrypt_aes(payload[aes_key_index], key, iv)
            except Exception as e:
                logger.error(f"Error is your password correct? {e}, exiting")
                exit(1)

            self.ticket = raw_data[ticket_size:]

            # checks that the Nonce match the Nonce sent.
            if self.nonce != decrypt_aes(payload[nonce_index], key, iv):
                raise "server's Nonce is wrong, aborting"

            self.key_request_waiting = False

        if response_code == CODE.MSG_SERVER_ACCEPTED_SYMMETRIC_KEY.value:
            print("Message server received Symmetric key")
        if response_code == CODE.MSG_SERVER_ACCEPTED_MESSAGE.value:
            print("Message server printed your message")
        if response_code == CODE.GENERAL_ERROR_IN_SERVER.value:
            print("A General Error occurred in server")

    def connect_to_msg_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = sock
        sock.connect((self.message_server_address, self.message_server_port))
        self.check_connection()

        # sends the symmetric key to server message
        print("\nSending Ticket & auth to message server")
        msg = Message.send_aes_key_to_msg_server(self.symmetric_key_for_msg_server, self.ticket, self.version,
                                                 self.client_id, self.server_id,
                                                 CODE.CLIENT_SENDING_KEY_TO_SERVER_MSG.value)
        self.socket.send(msg)

    def get_user_msg(self):
        while True:
            # checks if there is a message in the buffer form the server message
            self.recv_messages()
            message = input("Enter your message")
            msg = Message.encrypted_message(self.client_id, self.version,
                                            CODE.CLIENT_SENDING_MSG_TO_SERVER_MSG.value,
                                            message.encode(), self.symmetric_key_for_msg_server)
            self.socket.send(msg)
            time.sleep(0.1)


if __name__ == '__main__':
    client = Client()
    client.start()
