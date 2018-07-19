from getpass import getpass
from base64 import (b64encode, b64decode)
import sys, socket, threading, select, libnacl.secret, libnacl.utils, libnacl.sealed
from Tkinter import *
import time

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
    except (ValueError, libnacl.CryptError):
        cipher_text = ""
    return cipher_text

def salsa_decrypt(data, safe):
    try:
        plain_text = safe.decrypt(data)
    except (ValueError, libnacl.CryptError):
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
            response = r.recv(2048)
            response = salsa_decrypt(response, safe)
            gui.write(response)
            
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

    def send(self, data):
        buf = self.safe.encrypt(data)
        self.s.send(buf)

    def shutdown(self):
        self.s.close()

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
        sockets = []
        sockets.append(self.s)
        menu = self.s.recv(1024)
        if menu != "":
            self.online = True
            menu = salsa_decrypt(menu, self.safe)
            gui.write(menu)
            threading.Thread(target=recv_thread, args=(sockets, self.safe)).start()
        else:
            self.online = False

class StreamGui(Frame):

    def shutdown(self):
        client.send("exit")
        client.shutdown()
        sys.exit(0)

    def createWidgets(self):
        self.display = Text(self, height=35, width=100)
        self.display.pack()
        self.exit = Button(self)
        self.exit["text"]  = "Exit"
        self.exit["command"] = self.shutdown

        self.exit.pack({"side": "left"})
        self.input_field = Entry(self.master, bd=5)
        self.input_field.pack(side=RIGHT)
        self.input_field.config(width=25)
        self.sendbutton = Button(self.master, text="Send", width=10, command=self.send)
        self.sendbutton.pack(side=LEFT)

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.master.bind('<Return>', self.send_msg)
        self.otr = False
        self.createWidgets()
    
    def send(self):
        msg = self.input_field.get()
        if msg == "otr":
            self.otr == True
        self.input_field.delete(0, 'end')
        client.send(msg)

    def send_msg(self, event):
        self.send()

    def write(self, data):
        if self.otr == False:
            self.display.delete('1.0', END)
        self.display.insert(END, data+"\n")

root = Tk()
gui = StreamGui(master=root)
client = StreamClient(server, port, user, password)
client.connect()
if client.online == True:
    gui.mainloop()
    root.destroy()
