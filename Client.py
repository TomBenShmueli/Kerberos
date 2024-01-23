import pickle
import socket
import time
from logging import Logger

logger = Logger("")


def _is_socket_connected(s: socket.socket) -> bool:
    try:
        s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        return True
    except socket.error as e:
        print(e)
        return False


class Connection:
    address = "127.0.0.1"
    port = 65432

    socket: socket = None
    is_connected: bool = False

    def check_connection(self):
        self.is_connected = _is_socket_connected(self.socket)

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = sock
        sock.connect((self.address, self.port))
        self.check_connection()

    def recv_messages(self):
        if not self.is_connected:
            time.sleep(0.01)

        try:
            raw_data = self.socket.recv(4096)
            if raw_data:
                print(raw_data)
            else:
                pass
        except ConnectionResetError as e:
            logger.info("{}".format(e))
        except ConnectionAbortedError as e:
            logger.info("connection was aborted by the software in your host machine")

    def send_msg(self, msg: str) -> int:
        if len(pickle.dumps(msg)) > 4095:
            logger.info("Error: message is too big")

        return self._send_msg(pickle.dumps(msg))

    def _send_msg(self, msg) -> int:
        try:
            return self.socket.send(msg)
        except Exception as e:
            print(e)
            raise Exception("Could not have sent Message")

    def disconnect(self):
        self.socket.close()
        self.is_connected = False


if __name__ == '__main__':
    connection = Connection()
    connection.connect()
    connection.send_msg("Test Message...")