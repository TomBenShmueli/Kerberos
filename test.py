import struct
import unittest
from unittest.mock import MagicMock
from Client import Connection, Message, CODE


class ClientTests(unittest.TestCase):
    def test_client_response(self):
        conn = Connection()
        raw_data = struct.pack("<bHI16s", 24, 1600, 16, "64f3f63985f04beb81a0e43321880182".encode("utf-8"))
        conn.analyze_response(raw_data)
        # self.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()
