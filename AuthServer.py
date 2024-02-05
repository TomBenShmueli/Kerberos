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

    def clients_boot_read_data(self,file_path):
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
            request = struct.unpack("<16sbHI", recv_data[:23])
            request_code = request[2]
            print(request)
            #  Parse data and store in a variable
            if request_code == RequestCode.CLIENT_REQUEST_SIGNUP.value:
                return self.register_new_client(self, sock, request)
                pass
            elif request_code == RequestCode.CLIENT_REQUEST_AES_KEY_FOR_SERVER_MSG.value:
                return self.generate_key_and_ticket(self, sock, recv_data)
                pass

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
        client_socket, client_addr = server_socket.accept()
        print(f"Generating key for client addr  {client_addr}")

        # Server sends a session key
        session_key = self.generate_key()
        client_socket.send(session_key)

        # Server receives authentication request and performs a lookup on the user
        username = struct.unpack("<255s255s", recv_data[23:])
        if clients_db.is_client_authorized(username):
            # Step 3: Server sends a TGT (Ticket-Granting Ticket)
            tgt = SHA256.new(data=session_key.encode()).digest()
            client_socket.send(tgt)

            # Step 4: Server receives a request for a service ticket
            service_name = client_socket.recv(1024).decode()

            # Step 5: Server sends a service ticket
            service_ticket = self.encrypt(session_key, f"{service_name}:{session_key.hex()}")
            client_socket.send(service_ticket[0])  # Sending ciphertext
            client_socket.send(service_ticket[1])  # Sending tag

            print(f"Authentication successful for user {username} accessing service {service_name}")
        else:
            print(f"Authentication failed for user {username}")

        client_socket.close()

    def register_new_client(self, server_socket, request):
        new_uuid = uuid.uuid4()
        client_socket, client_addr = server_socket.accept()
        print(f'Registering new user...')

        username = request[3]
        password = self.encrypt(request[4])
        if clients_db.is_client_authorized(username):
            try:
                clients_db.clients_write_data(new_uuid, username, password, datetime.now())
                return client_socket.send(RESPONSE.AUTH_SERVER_REGISTRATION_SUCCESS)
            except Exception:  # db write failure
                return client_socket.send(RESPONSE.AUTH_SERVER_REGISTRATION_FAIL)
        else:  # user already exists
            return client_socket.send(RESPONSE.AUTH_SERVER_REGISTRATION_FAIL)
        pass


if __name__ == '__main__':
    server = AuthServer()
    server.start_server()
