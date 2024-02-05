import datetime
import os
import selectors
import socket
import struct
import uuid
from enum import Enum
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from logging import Logger

logger = Logger("")


class ClientFauxDB:
    def __init__(self, file_path):
        self.file_path = file_path
        self.clients_data = self.clients_boot_read_data(file_path)

    def clients_write_data(self, user_id, user_name, pw_hash, last_seen):
        with open(self.file_path, 'a') as file:
            file.write(f"'{user_id}:{user_name}:{pw_hash}:{last_seen}\n")

    def clients_boot_read_data(self, file_path):
        if not os.path.exists("clients"):  # Clients file missing
            logger.error(f"Client file cannot be found. Defaulting to empty dataset...")
            return []

        with open(file_path, 'r') as clients_file:  # Read from "Clients" file and create the faux DB
            file_content = clients_file.read()

            # client data processed into rows
            clients_raw_data = [rawData.strip() for rawData in file_content.split('\n') if rawData]

            # parse data from the following format ID:Name:PasswordHash:LastSeen to objects for faster performance
            clients_data = []
            for rawData in clients_raw_data:
                rawDataSubString = rawData.split(':')  # assuming data integrity from file
                newDataEntry = {'ID': rawDataSubString[0],
                                'Name': rawDataSubString[1],
                                'PasswordHash': rawDataSubString[2],
                                'LastSeen': rawDataSubString[3]}
                clients_data.append(newDataEntry)
            return clients_data
        return

    def is_client_authorized(self, client_username):
        if not self.clients_data:
            return False
        else:
            for iterable in self.clients_data:
                if iterable[2] == client_username:
                    return True


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

    socket: socket = None

    def __init__(self):
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

        # read from socket
        if mask & selectors.EVENT_READ:
            self.receive_data(key)
        # send data to socket
        if mask & selectors.EVENT_WRITE:
            pass

    def receive_data(self, key):
        sock: socket.socket = key.fileobj

        #  makeshift API gateway
        try:
            recv_data = sock.recv(4096)  # 4kb buffer size
            print(recv_data)
            #  recv_data contains the request data and the header to redirect request to the correct server function
            request_headers = struct.unpack("<16sbHI", recv_data[:23])
            request_code = request_headers[2]
            print(request_headers)
            #  Parse data and store in a variable
            if request_code == RequestCode.CLIENT_REQUEST_SIGNUP.value:
                payload = struct.unpack("<255s255s", recv_data[23:])
                return self.register_new_client(request_headers, payload)
            elif request_code == RequestCode.CLIENT_REQUEST_AES_KEY_FOR_SERVER_MSG.value:
                return self.generate_key_and_ticket(sock, recv_data)

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

    def send_msg(self, msg: str) -> int:
        if len(msg) < 4095:
            logger.info("Error: message is too big")
            try:
                return self.socket.send(msg)
            except Exception as e:
                print(e)
                raise Exception("Could not have sent Message")

    @staticmethod
    def generate_key():
        return get_random_bytes(32)  # 32 bytes for AES-128

    @staticmethod
    def encrypt(key, data):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return ciphertext, tag

    @staticmethod
    def decrypt(key, ciphertext, tag):
        cipher = AES.new(key, AES.MODE_EAX)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()

    def derive_key(password):
        hash_object = SHA256.new(data=password.encode())
        return hash_object.digest()

    def generate_key_and_ticket(self, server_socket, recv_data):

        # Server sends a session key
        session_key = self.generate_key()
        self.socket.send(session_key)

        # Server receives authentication request and performs a lookup on the user
        username = struct.unpack("<255s255s", recv_data[23:])
        if clients_db.is_client_authorized(username):
            # Step 3: Server sends a TGT (Ticket-Granting Ticket)
            tgt = SHA256.new(data=session_key.encode()).digest()
            self.send_msg(str(tgt))

            # Step 4: Server receives a request for a service ticket
            # service_name = client_socket.recv(1024).decode()
            #
            # # Step 5: Server sends a service ticket
            # service_ticket = self.encrypt(session_key, f"{service_name}:{session_key.hex()}")
            # client_socket.send(service_ticket[0])  # Sending ciphertext
            # client_socket.send(service_ticket[1])  # Sending tag

    def register_new_client(self, request_headers, payload):
        new_uuid = uuid.uuid4()
        print(f'Registering new user...')

        username = payload[0]
        password = self.encrypt(payload[1])
        if clients_db.is_client_authorized(username):
            try:
                clients_db.clients_write_data(new_uuid, username, password, datetime.now())
                payload_size = len(request_headers[0])
                response = struct.pack(f"<bHI16s", self.server_version, RESPONSE.AUTH_SERVER_REGISTRATION_SUCCESS,
                                       payload_size.to_bytes(4, byteorder='little'), new_uuid)
                return self.send_msg(response)
            except Exception:  # db write failure
                payload_size = len(request_headers[0])
                response = struct.pack(f"<bHI16s", self.server_version, RESPONSE.AUTH_SERVER_REGISTRATION_FAIL,
                                       payload_size.to_bytes(4, byteorder='little'), new_uuid)
                return self.send_msg(response)
        else:  # user already exists
            return self.send_msg(RESPONSE.AUTH_SERVER_REGISTRATION_FAIL)
        pass


if __name__ == '__main__':
    server = AuthServer()
    server.start_server()
