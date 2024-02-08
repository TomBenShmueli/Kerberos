import base64
import os
import selectors
import socket
import struct
from logging import Logger

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

logger = Logger("")


def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_CBC, get_random_bytes(AES.block_size))
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ciphertext


def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data


class MessageServer:
    HOST = "127.0.0.1"
    PORT = 65432
    name: str
    uuid: str
    servers_password: bytes

    sel = selectors.DefaultSelector()

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
        print(recv_data)
        authenticator = struct.unpack("<16s16s32s32s16s", recv_data[:112])
        ticket = struct.unpack("<B16s16sQ16s48s24s", recv_data[112:])

        print(ticket[4])
        aes_key = decrypt_aes(ticket[5], self.servers_password, ticket[4])
        print(f"symmetric key with client : {aes_key}")
        pass


if __name__ == '__main__':
    server = MessageServer()
    server.start_server()
