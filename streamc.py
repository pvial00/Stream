from getpass import getpass
from base64 import (b64encode, b64decode)
import sys, socket, threading, select, libnacl.secret, libnacl.utils, libnacl.sealed

try:
    server = sys.argv[1]
except IndexError as ier:
    print "Usage: streamc.py <hostname>"
    sys.exit(1)

port = 64666
user = raw_input("login:")
password = getpass("password:")

def rsa_encrypt(data, public_key):
    srv_safe = libnacl.sealed.SealedBox(public_key)
    cipher_text = srv_safe.encrypt(data)
    return cipher_text

def salsa_encrypt(data, safe):
    try:
        cipher_text = safe.encrypt(data)
    except libnacl.exceptions.CryptoError:
        cipher_text = ""
    return cipher_text

def salsa_decrypt(data, safe):
    try:
        plain_text = safe.decrypt(data)
    except libnacl.exceptions.CryptoError:
        plain_text = ""
    return plain_text

def auth_pkg(user, passw, session_key):
    return user + ":" + passw + ":" + session_key

def gen_session_key():
    session_key = libnacl.utils.salsa_key()
    return session_key

def recv_thread(sock, safe):
    while sock:
        try:
            readable, writable, errable = select.select(sock, sock, sock)
        except socket.error as ser:
            break
        for r in readable:
            room_chat = r.recv(2048)
            room_chat = salsa_decrypt(room_chat, safe)
            sys.stdout.write(room_chat+"\n")
            
class StreamClient:
    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.user = user
        self.passw = libnacl.crypto_hash(password)
        self.session_key = gen_session_key()
        self.safe = libnacl.secret.SecretBox(self.session_key)
        self.session_pkg = auth_pkg(self.user, self.passw, self.session_key)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_id = "StreamClient"

    def connect(self):
        try:
            self.s.connect((self.host, self.port))
        except socket.error as ser:
            print "Error: Unable to connect to server, try again."
            sys.exit(1)
        client_id = b64encode(self.client_id)
        try:
            self.s.send(client_id)
        except socket.error as ser:
            print "Error: Unable to connect to server, try again."
            sys.exit(1)

        server_key = self.s.recv(2048)
        server_key = b64decode(server_key)
        session_pkg = auth_pkg(self.user, self.passw, self.session_key)
        self.session_key = ""
        session_pkg = rsa_encrypt(self.session_pkg, server_key)
        self.s.send(session_pkg)
        menu = self.s.recv(1024)
        if menu != "":
            mmenu = salsa_decrypt(menu, self.safe)
            print mmenu
            room = raw_input()
            room = room.rstrip("\r\n")
            myroom = salsa_encrypt(room, self.safe)
            self.s.send(myroom)
            if room != "exit" and room != "leave":
                room_chat = self.s.recv(2048)
                room_chat = salsa_decrypt(room_chat, self.safe)
                print room_chat
                sockets = []
                sockets.append(self.s)
                threading.Thread(target=recv_thread, args=(sockets, self.safe)).start()
                while True:
                    msg = raw_input()
                    if msg == "exit":
                        msg = salsa_encrypt(msg, self.safe)
                        self.s.send(msg)
                        break
                    msg = salsa_encrypt(msg, self.safe)
                    self.s.send(msg)
            else:
                self.s.close()
        self.s.close()

client = StreamClient(server, port, user, password).connect()
