import base64
import time
from datetime import datetime
import os
import selectors
import socket
import struct
import uuid
from enum import Enum
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from logging import Logger
import queue

logger = Logger("")


class ClientFauxDB:
    def __init__(self, file_path):
        self.file_path = file_path
        self.clients_data = self.clients_boot_read_data(file_path)

    def clients_write_data(self, user_id, user_name, pw_hash, last_seen):
        with open(self.file_path, 'a') as file:
            file.write(f"{user_id}:{user_name}:{pw_hash}:{last_seen}\n")

        new_data_entry = {'ID': user_id,
                          'Name': user_name,
                          'PasswordHash': pw_hash,
                          'LastSeen': last_seen}
        self.clients_data.append(new_data_entry)

    @staticmethod
    def clients_boot_read_data(file_path):
        if not os.path.exists("clients"):  # Clients file missing
            logger.error(f"Client file cannot be found. Defaulting to empty dataset...")
            return []
        try:
            with open(file_path, 'r') as clients_file:  # Read from "Clients" file and create the faux DB
                file_content = clients_file.read()

                # client data processed into rows
                clients_raw_data = [rawData.strip() for rawData in file_content.split('\n') if rawData]

                # parse data from the following format ID:Name:PasswordHash:LastSeen to objects for faster performance
                clients_data = []
                for rawData in clients_raw_data:
                    raw_data_sub_string = rawData.split(':')  # assuming data integrity from file
                    new_data_entry = {'ID': raw_data_sub_string[0],
                                      'Name': raw_data_sub_string[1],
                                      'PasswordHash': raw_data_sub_string[2],
                                      'LastSeen': raw_data_sub_string[3]}
                    clients_data.append(new_data_entry)
                return clients_data
        except Exception as e:
            logger.error(f'Failed to read from faux DB' + e)
            return []

    def is_username_exists(self, username):
        if not self.clients_data:
            return False
        else:
            for client in self.clients_data:
                if client["Name"] == username:
                    return True
            return False

    def is_id_exists(self, id):
        if not self.clients_data:
            return False
        else:
            for client in self.clients_data:
                if str(client["ID"]) == id.strip():
                    return True
            return False

    def get_password(self, id):
        for client in self.clients_data:
            if str(client["ID"]) == id:
                return client["PasswordHash"]


clients_db = ClientFauxDB('clients')


class RequestCode(Enum):
    CLIENT_REQUEST_SIGNUP = 1024
    CLIENT_REQUEST_AES_KEY_FOR_SERVER_MSG = 1027

    #     Message server
    ACKE_ACCEPTED_SYMMETRIC_KEY = 1604
    ACKE_ACCEPTED_MESSAGE = 1605
    GENERAL_ERROR_IN_SERVER = 1609


class RESPONSE(Enum):
    AUTH_SERVER_REGISTRATION_SUCCESS = 1600
    AUTH_SERVER_REGISTRATION_FAIL = 1601

    SYMMETRIC_KEY_SUCCESS = 1603


class AuthServer:
    HOST = "127.0.0.1"
    PORT = 1256
    VERSION = 24
    sel = selectors.DefaultSelector()

    messages = queue.Queue()
    socket: socket = None

    def __init__(self):
        self.data = None
        if not os.path.exists("port.info"):
            logger.error(f"Port.info file doesn't exists, defaults to port 1256")
        else:
            with open("port.info", 'r') as file:
                self.PORT = file.readline()

    def start_server(self):
        """
        listening to incoming connection requests.
        """
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:

            server_socket.bind((self.HOST, int(self.PORT)))
            server_socket.listen()
            server_socket.setblocking(False)
            self.sel.register(server_socket, selectors.EVENT_READ, data=None)
            try:
                while True:
                    events = self.sel.select(timeout=None)
                    for key, mask in events:
                        if key.data is None:
                            self.accept_wrapper(key.fileobj)
                        else:
                            self.service_connection(key, mask)

            except KeyboardInterrupt:
                print("keyboard interrupt")
            finally:
                self.sel.close()

    def accept_wrapper(self, sock):
        """
        accepting connection requests and adding them to the socket_info data structure
        :param sock: the socket itself that was accepted.
        """
        self.socket = sock
        conn: socket.socket
        conn, addr = sock.accept()
        conn.setblocking(False)
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(conn, events, data=addr)

    def service_connection(self, key, mask):
        """
        multiplexing between the open sockets and services them.
        :param key: contains the socket.
        :param mask: contains data about the socket.
        """
        sock = key.fileobj
        self.data = key.data

        # read from socket
        if mask & selectors.EVENT_READ:
            self.receive_data(key)
        # send data to socket
        if mask & selectors.EVENT_WRITE and not self.messages.empty():
            message = self.messages.get(False)
            sock.send(message)

    def receive_data(self, key):
        sock: socket.socket = key.fileobj

        #  makeshift API gateway
        try:
            recv_data = sock.recv(4096)  # 4kb buffer size
            print(recv_data)
            #  recv_data contains the request data and the header to redirect request to the correct server function
            request_headers = struct.unpack("<16sBHI", recv_data[:23])
            request_code = request_headers[2]
            print(request_headers)
            #  Parse data and store in a variable
            if request_code == RequestCode.CLIENT_REQUEST_SIGNUP.value:
                payload = struct.unpack("<255s255s", recv_data[23:])
                return self.register_new_client(request_headers, payload)
            elif request_code == RequestCode.CLIENT_REQUEST_AES_KEY_FOR_SERVER_MSG.value:
                return self.generate_key_and_ticket(request_headers, recv_data[23:])

        except ConnectionResetError:
            logger.debug("An existing connection was forcibly closed by the remote host")
            self.sel.unregister(sock)
            sock.close()

        except Exception:  # placeholder to prevent server crash
            logger.debug("General Exception")
            self.sel.unregister(sock)
            sock.close()
            return

        if not recv_data:
            return

    def send_msg(self, msg: Any) -> int:
        if len(msg) < 4095:
            logger.info("Error: message is too big")
            try:
                return self.socket.send(msg)
            except Exception as e:
                print(e)
                raise Exception("Could not have sent Message")

    def generate_key_and_ticket(self, headers, payload):

        client_id = str(uuid.UUID(bytes=headers[0]))
        payload = struct.unpack("<16sQ", payload)
        # todo change so that we read the server id from srv.info
        server_id = payload[0].decode()
        nonce = payload[1]
        iv = self.generate_iv()

        # Server sends a session key
        aes_key = self.generate_key()

        # Server receives authentication request and performs a lookup on the user
        if clients_db.is_id_exists(client_id):

            try:
                client_id_field = struct.pack("<16s", uuid.UUID(client_id).bytes)
                encrypted_key_field = struct.pack("<16s", iv) + self.create_key_field(aes_key, client_id, nonce, iv)
                ticket_field = self.create_ticket_field(client_id, server_id, aes_key)

                payload_size = len(client_id_field) + len(encrypted_key_field) + len(ticket_field)
                headers_response = struct.pack("<BHI", self.VERSION, RESPONSE.SYMMETRIC_KEY_SUCCESS.value,
                                               payload_size)
                response_payload = client_id_field + encrypted_key_field + ticket_field

                response = headers_response + response_payload
                print("sent client AES encryption key successfully")
                self.messages.put(response)
            except Exception as e:
                print(e)
        else:
            print("client id not exists")
            # Todo should return message with fail code
            pass

    def create_key_field(self, aes_key, client_id, nonce, iv):
        client_hashed_password = clients_db.get_password(client_id)
        client_hashed_password = bytes.fromhex(client_hashed_password)

        data = int.to_bytes(nonce, 8, "little")
        encrypted_nonce = self.encrypt_aes(data, client_hashed_password, iv)
        encrypted_aes_key = self.encrypt_aes(bytes(aes_key), client_hashed_password, iv)

        print(f"bytes fo aes key:,{bytes(aes_key)}")
        # print(f"decrypt aes key: {self.decrypt_aes(encrypted_aes_key, client_hashed_password, iv)}")

        return struct.pack("<16s48s", encrypted_nonce, encrypted_aes_key)

    def create_ticket_field(self, client_id, server_id, aes_key):

        current_timestamp = int(time.time())

        # Add 3600 seconds (1 hour) to the current timestamp
        expiration_timestamp = current_timestamp + 3600

        ticket_iv = self.generate_iv()

        # Todo change server id it's not coming as it should from the client
        part_1 = struct.pack("<B16s16sQ16s", self.VERSION, client_id.encode(), server_id.encode(),
                             current_timestamp, ticket_iv)

        # To read from msg.info
        hashed_msg_server_password: bytes
        with open("msg.info", "r") as msg_file:
            msg_file.readline()
            msg_file.readline()
            msg_file.readline()
            line = msg_file.readline()
            hashed_msg_server_password = base64.b64decode(line)

        print(f"ticket iv {ticket_iv}")
        encrypted_aes_key = self.encrypt_aes(bytes(aes_key), hashed_msg_server_password, ticket_iv)

        time_expiration_bytes = int.to_bytes(expiration_timestamp, 8, "little")
        encrypted_expiration_time = self.encrypt_aes(time_expiration_bytes, hashed_msg_server_password, ticket_iv)

        part_2 = struct.pack("<48s16s", encrypted_aes_key, encrypted_expiration_time)

        print("ticket bytes")
        print(part_1 + part_2)
        return part_1 + part_2

    def register_new_client(self, request_headers, payload):
        new_uuid = uuid.uuid4()
        print(f'Registering new user...')

        username = self.remove_null_termination(payload[0].decode("ascii"))
        password = self.remove_null_termination(payload[1].decode("ascii"))
        password = SHA256.new(password.encode()).hexdigest()

        if not clients_db.is_username_exists(username):
            try:
                clients_db.clients_write_data(new_uuid, username, password, datetime.now())
                response = struct.pack(f"<BHI16s", self.VERSION, RESPONSE.AUTH_SERVER_REGISTRATION_SUCCESS.value,
                                       4, new_uuid.bytes)
                logger.info(f'User {username} was registered successfully.')
                self.messages.put(response)
            except Exception as e:  # db write failure
                print(e)
                payload_size = len(request_headers[0])
                response = struct.pack(f"<bHI16s", self.VERSION, RESPONSE.AUTH_SERVER_REGISTRATION_FAIL,
                                       payload_size.to_bytes(4, byteorder='little'), new_uuid)
                self.messages.put(response)
        else:  # user already exists
            logger.info(f'User {username} is already registered.')
            payload_size = 0
            response = struct.pack(f"<bHI", self.VERSION, RESPONSE.AUTH_SERVER_REGISTRATION_FAIL,
                                   payload_size.to_bytes(0, byteorder='little'))
            return self.messages.put(response)

    @staticmethod
    def generate_iv():
        return get_random_bytes(16)  # 16 bytes for IV

    @staticmethod
    def generate_key():
        return get_random_bytes(32)  # 32 bytes for AES-256

    @staticmethod
    def encrypt_aes(data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return ciphertext

    @staticmethod
    def remove_null_termination(string: str):
        return string[:string.find("\\0")]


if __name__ == '__main__':
    server = AuthServer()
    server.start_server()
