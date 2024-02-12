import base64
import datetime
import os
import queue
import selectors
import socket
import struct
from enum import Enum
from logging import Logger

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

logger = Logger("")


class CODE(Enum):
    CLIENT_SENDING_KEY_TO_SERVER_MSG = 1028
    CLIENT_SENDING_MSG_TO_SERVER_MSG = 1029

    AES_KEY_RECEIVED = 1604
    MSG_RECEIVED = 1605

    GENERAL_ERROR = 1609


def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data


class Message:
    version: int
    code: int
    payload_size: int
    payload: any

    def __init__(self, version: int, code: int, payload_size: int, payload):
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.payload = payload

    def get_bytes(self):
        """
        turns the class into packed bytes
        :return: returns the whole message packed to bytes with header & payload
        """
        if not self.payload:
            return struct.pack("<BHI", self.version, self.code,
                               self.payload_size)
        else:
            return struct.pack("<BHI", self.version, self.code,
                               self.payload_size) + self.payload

    @staticmethod
    def symmetric_key_confirmation(version):
        return Message(version, CODE.AES_KEY_RECEIVED.value, 0, None).get_bytes()

    @staticmethod
    def message_received(version):
        return Message(version, CODE.MSG_RECEIVED.value, 0, None).get_bytes()

    @staticmethod
    def error_response(version):
        payload_size = 0
        response = struct.pack(f"<BHI", version, CODE.GENERAL_ERROR.value, payload_size)
        return response


class MessageServer:
    HOST: str
    PORT: int
    name: str
    uuid: str
    servers_password: bytes

    version = 24

    users_data = {}

    sel = selectors.DefaultSelector()

    messages = queue.Queue()
    socket: socket = None

    def __init__(self):
        if not os.path.exists("msg.info"):
            logger.error(f"msg.info file doesn't exists")
        else:
            with open("msg.info", 'r') as file:
                server_port = file.readline()
                self.HOST = server_port[:server_port.find(":")]
                self.PORT = int(server_port[server_port.find(":") + 1:])

                # strips the \n
                self.name = file.readline()[:-1]
                self.uuid = file.readline()[:-1]
                password = file.readline()
                self.servers_password = base64.b64decode(password)

    def start_server(self):
        """
        listening to incoming connection requests.
        """
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            print('Server is now listening on ' + str(self.PORT) + '...')
            s.setblocking(False)
            self.sel.register(s, selectors.EVENT_READ, data=None)
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
        # read from socket
        if mask & selectors.EVENT_READ:
            self.receive_data(key)
        # send data to socket
        if mask & selectors.EVENT_WRITE and not self.messages.empty():
            message = self.messages.get(False)
            sock.send(message)

    def receive_data(self, key):
        sock: socket.socket = key.fileobj
        recv_data = None

        try:
            recv_data = sock.recv(4096)
            if recv_data:
                self.analyze_data(recv_data)
        except ConnectionResetError:
            logger.debug("An existing connection was forcibly closed by the remote HOST")
            self.sel.unregister(sock)
            sock.close()

        if not recv_data:
            return

    def analyze_data(self, recv_data):
        """
        analyze the data that is received and acts as an api gateway
        :param recv_data: the data that received
        """
        try:
            header = struct.unpack("<16sBHI", recv_data[:23])
            message_code = header[2]

            if message_code == CODE.CLIENT_SENDING_KEY_TO_SERVER_MSG.value:
                authenticator = struct.unpack("<16s16s32s32s16s", recv_data[23:135])
                ticket = struct.unpack("<B16s16sQ16s48s16s", recv_data[135:])
                ticket_iv = ticket[4]
                authenticator_iv = authenticator[0]
                client_id_ticket = ticket[1]

                aes_key = decrypt_aes(ticket[5], self.servers_password, ticket_iv)
                expiration_timestamp = decrypt_aes(ticket[6], self.servers_password, ticket_iv)
                expiration_timestamp = int.from_bytes(expiration_timestamp, "little")
                expiration_timestamp = datetime.datetime.fromtimestamp(expiration_timestamp)

                authenticator_client_id = decrypt_aes(authenticator[2], aes_key, authenticator_iv)
                if client_id_ticket != authenticator_client_id:
                    raise "client id in ticket and auth do not match"

                self.users_data[str(client_id_ticket)] = (aes_key, expiration_timestamp)

                # confirm to client that the message received
                print("Received ticket & auth from client ")
                self.messages.put(Message.symmetric_key_confirmation(self.version))
            if message_code == CODE.CLIENT_SENDING_MSG_TO_SERVER_MSG.value:
                payload = struct.unpack("<I16s", recv_data[23:43])
                client_id = header[0]
                msg_size = payload[0]
                iv = payload[1]

                message = struct.unpack(f"<{msg_size}s", recv_data[43:])

                if not self.users_data.get(str(client_id)):
                    self.messages.put(Message.error_response(self.version))
                    print("client id not found")
                    return

                # first index is the aes key
                key = self.users_data.get(str(client_id))[0]
                # second index is the expiration timestamp
                expiration_timestamp = self.users_data.get(str(client_id))[1]

                current_time = datetime.datetime.now()
                if current_time > expiration_timestamp:
                    self.messages.put(Message.error_response(self.version))
                    print("Ticket timestamp expired please ask for a new key from Auth server")
                    return

                # prints client message
                print(decrypt_aes(message[0], key, iv).decode())

                # send messages back to confirm the message received
                self.messages.put(Message.message_received(self.version))

        except Exception as e:
            # returns general error response code
            print("An error occurred:" + str(e))
            print("returns client error response code")
            self.messages.put(Message.error_response(self.version))


if __name__ == '__main__':
    server = MessageServer()
    server.start_server()
