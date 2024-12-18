from pwn import *
from checklib import *
import random

context.log_level = 'CRITICAL'
# context.log_level = "debug"

PORT = 12345
HOST = "0"
DEFAULT_RECV_SIZE = 4096
TCP_CONNECTION_TIMEOUT = 5
TCP_OPERATIONS_TIMEOUT = 7

class CheckMachine:

    def __init__(self, checker: BaseChecker):
        self.c = checker
        self.port = PORT

    def connection(self) -> remote:
        io = remote(self.c.host, self.port, timeout=TCP_CONNECTION_TIMEOUT)
        io.settimeout(TCP_OPERATIONS_TIMEOUT)
        return io

    def Check_SeaDrink(self, io: remote, sth: str, status: Status) -> None:
        io.sendafter(b"Enter: ", b"1")
        io.sendlineafter(b"Enter Drink: ", sth.encode())
        resp = io.recvline().strip()
        self.c.assert_eq(resp, b"Here your drink", b"Invalid Drink", status)


    def showflag(self, io: remote):
        def getoutput():
            e = process("./AES_test")
            return e.recv().strip()
        out = getoutput()

        io.sendlineafter(b"Enter:", b"1")
        io.sendlineafter(b"Enter Drink: ", out)
        io.recvline()
        resp = io.recvline().strip()
        return resp

    def quit(self, io: remote, num: str) -> None:
        io.sendlineafter(b"Enter: ", num.encode())

    def register(self, io: remote, username: str, password: str, drink: str, status: Status) -> None:
        io.sendlineafter(b'Enter: ', b'2')
        io.sendlineafter(b'Username: ', username.encode())
        io.sendlineafter(b'Password: ', password.encode())
        io.sendlineafter(b'Drink: ', drink.encode())
        resp = io.recvline().strip()
        self.c.assert_eq(resp, b'Register successful', b'Invalid response on register', status)

    def login(self, io: remote, username: str, password: str, status: Status) -> None:
        io.sendlineafter(b'Enter: ', b'1')
        io.sendlineafter(b'Username: ', username.encode())
        io.sendlineafter(b'Password: ', password.encode())
        resp = io.recvline().strip()
        self.c.assert_eq(resp, b'Login successful.', b'Invalid response on login', status)