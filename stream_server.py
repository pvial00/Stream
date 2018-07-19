from base64 import (b64encode, b64decode)
import sys, socket, threading, select, os
import libnacl.secret, libnacl.utils, libnacl.public, libnacl.sealed

host = "0.0.0.0"
port = 64666
univeral_id = "StreamClient"
stream_contents = "admin: Welcome to Stream Chat!\n"
tech_contents = "admin: Welcome to Tech Chat!\n"
general_contents = "admin: Welcome to General Chat!\n"
dbfile = "stream.db"
passkey = "5%9Bd@3gUi$5KPqS7$TBm9201A35%bB#"
stream_users_online = {}
online_sockets = {}
debug = False

if os.path.isfile(dbfile) == False:
    print "Error: Password database is missing."
    sys.exit(1)

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

def gen_server_keypair():
    keypair = libnacl.public.SecretKey()
    return keypair

def gen_session_key():
    session_key = libnacl.utils.salsa_key()
    return session_key

def recv(sock, buf_size):
    try:
        data = sock.recv(buf_size)
    except socket.error as ser:
        if debug == True:
            print ser
        sock.close()
        data = ""
    return data

def send(sock, data):
    try:
        sock.send(data)
    except socket.error as ser:
        if debug == True:
            print ser
        sock.close()
        data = ""
    return data

class Room:
    def __init__(self, name, contents, private, reservations):
        master_key = gen_session_key()
        self.safe = libnacl.secret.SecretBox(master_key)
        master_key = ""
        self.name = name
        self.contents = contents
        self.contents = salsa_encrypt(contents, self.safe)
        self.users_online = {}
        self.sockets = {}
        self.private = private
        self.otr = False
        self.reservations = reservations

    def write(self, user, msg):
        if user in self.users_online:
            if self.otr == False:
                contents = salsa_decrypt(self.contents, self.safe)
                entry = user + ": " + msg
                contents += entry
                contents = trim_room(contents)
                self.contents = salsa_encrypt(contents, self.safe)
                for write_user, write_user_obj in self.users_online.iteritems():
                    write_socket = self.sockets[write_user_obj.name]
                    payload = write_user_obj.safe.encrypt(contents)
                    send(write_socket, payload)

            elif self.otr == True and self.private == True:
                entry = user + ": " + msg
                for write_user, write_user_obj in self.users_online.iteritems():
                    write_socket = self.sockets[write_user_obj.name]
                    payload = write_user_obj.safe.encrypt(entry)
                    send(write_socket, payload)

    def read(self, user):
        if user.name in self.users_online:
            contents = salsa_decrypt(self.contents, self.safe)
        else:
            contents = "Access denied"
        return contents

    def join(self, user, socket):
        if user.name in self.reservations and self.private == True:
            self.users_online[user.name] = user
            self.sockets[user.name] = socket
            self.write(user.name, "joined the room")
            if debug == True:
                print self.name, self.users_online
                print self.name, self.sockets
        elif self.private == False:
            self.users_online[user.name] = user
            self.sockets[user.name] = socket
            self.write(user.name, "joined the room")
            if debug == True:
                print self.name, self.users_online
                print self.name, self.sockets
                print StreamServer.private_rooms

    def leave(self, user):
        self.write(user, "left the room")
        del self.users_online[user]
        del self.sockets[user]
        if debug == True:
            print self.name, self.users_online
            print self.name, self.sockets
            print StreamServer.private_rooms
        if self.private == True and len(self.reservations) == 2 and len(self.users_online) == 0:
            for pos in range(0,len(StreamServer.private_rooms)):
                check = StreamServer.private_rooms.pop(pos)
                if check.name != self.name:
                    StreamServer.private_rooms.insert(pos,check)
                else:
                    del StreamServer.rooms[self.name]

class User:
    def __init__(self, name, session_key):
        self.name = name
        self.safe = libnacl.secret.SecretBox(session_key)

def rsa_decrypt(data, private_safe):
    srv_safe = libnacl.sealed.SealedBox(private_safe)
    plain_text = srv_safe.decrypt(data)
    return plain_text

def process_auth_pkg(auth_pkg):
    elements = auth_pkg.split(':')
    user = elements.pop(0)
    passw = elements.pop(0)
    session_key = elements.pop(0)
    return user, passw, session_key

def validate_creds(user,passw):
    token = 0
    passfile = open(dbfile, "r")
    contents = passfile.read()
    passfile.close()
    passbox = libnacl.secret.SecretBox(passkey)
    contents = salsa_decrypt(contents, passbox)
    entries = contents.split("\n")
    for entry in entries:
        if user in entry:
            auth_items = entry.split(":")
            if passw == auth_items.pop(1):
                token = 1
    return token

def logout(user):
    if user.name in stream_users_online:
        try:
            del stream_users_online[user.name]
        except KeyError as ker:
            if debug == True:
                print ker
    try:
        del online_sockets[user.name]
    except KeyError as ker:
        if debug == True:
            print ker

def trim_room(contents):
    recent = ""
    num_lines = 35
    stream_length = len(contents.split('\n'))
    if stream_length >= num_lines:
        for line in reversed(range(0,num_lines)):
                position = stream_length - line
                recent += contents.split('\n')[position - 1] + "\n"
    else:
        recent = contents + "\n"
    return recent

def get_roomchat(user, room, socket):
    if room == 1:
        if user not  in StreamServer.general.users_online:
            StreamServer.general.join(user, socket)
        contents = StreamServer.general.read(user)
    elif room == 2:
        if user not  in StreamServer.tech.users_online:
            StreamServer.tech.join(user, socket)
        contents = StreamServer.tech.read(user)
    elif room == 3:
        if user not  in StreamServer.stream.users_online:
            StreamServer.stream.join(user, socket)
        contents = StreamServer.stream.read(user)
    elif room > 10:
        for speakeasy in StreamServer.private_rooms:
            if speakeasy.name == StreamServer.rooms[room]:
                if user not in speakeasy.users_online:
                    speakeasy.join(user, socket)
                if speakeasy.otr == True:
                    contents = ""
                else:
                    contents = speakeasy.read(user)
    return contents

def leave_room(user, room):
    if room == 1:
        if user in StreamServer.general.users_online:
            StreamServer.general.leave(user)
    elif room == 2:
        if user in StreamServer.tech.users_online:
            StreamServer.tech.leave(user)
    elif room == 3:
        if user in StreamServer.stream.users_online:
            StreamServer.stream.leave(user)
    elif room > 10:
        for speakeasy in StreamServer.private_rooms:
            if user in speakeasy.users_online:
                speakeasy.leave(user)

def otr(user, room):
    if room in StreamServer.rooms:
        for speakeasy in StreamServer.private_rooms:
            if user in speakeasy.users_online:
                speakeasy.otr = True

def append_msg(user, msg, room):
    if room == 1:
        StreamServer.general.write(user, msg)
    elif room == 2:
        StreamServer.tech.write(user, msg)
    elif room == 3:
        StreamServer.stream.write(user, msg)
    elif room > 10:
        for speakeasy in StreamServer.private_rooms:
            if speakeasy.name == StreamServer.rooms[room]:
                speakeasy.write(user, msg)

def num_check(string):
    try:
        int(string)
        return True
    except ValueError:
        return 

def main_menu_handler(c, user):
    banner = "Welcome t0 Stream Chat!\nType \"exit\" to logout\n"
    banner += "Please select a room to join\nType \"1\" for General Chat\nType \"2\" for Tech Chat\nType \"3\" for Stream Chat\nType \"9\" for Private Chats\nEnter a room number to join: "
    banner = salsa_encrypt(banner, user.safe)
    send(c, banner)
    room = recv(c, 1024)
    room = salsa_decrypt(room, user.safe)
    room = room.strip('\r\n')
    if room == "exit" or room == "leave":
        logout(user)
        c.close()
    elif room == "accept":
        if user.name in invites:
            room = invites[user.name]
            del invites[user.name]
            client_stream(c, user, room)
    elif num_check(room) == True:
        room = int(room)
        try:
            room_name = StreamServer.rooms[room]
            if room == 9:
                private_stream(c, user)
            else:
                client_stream(c, user, room)
        except KeyError:
            main_menu_handler(c, user)
    else:
        logout(user)
        c.close()

def gen_roomid():
    room_id = 0
    check = 0
    while room_id <= 10 and check == 0:
        room_id = ord(os.urandom(1))
        if room_id not in StreamServer.rooms:
            check = 1
        else:
            check = 0
    return room_id

def private_stream(sock1, user1):
    menu = "Choose a user to invite\n"
    for u, i in stream_users_online.iteritems():
        if u != user1.name:
            menu += u + "\n"
    menu = salsa_encrypt(menu, user1.safe)
    send(sock1, menu)
    puser = recv(sock1, 64)
    puser = salsa_decrypt(puser, user1.safe)
    if puser in stream_users_online:
        user2 = stream_users_online[puser]
        sock2 = online_sockets[user2.name]
        room_num = gen_roomid()
        content = "Speakeasy " + str(room_num) + "\n"
        reservations = []
        reservations.append(user1.name)
        reservations.append(user2.name)
        private_room = Room(room_num, content, True, reservations)
        StreamServer.private_rooms.append(private_room)
        StreamServer.rooms[room_num] = room_num
        invite_msg = user1.name + " has invited you to a private room. Type accept %d to accept\n" % room_num
        send(sock2, salsa_encrypt(invite_msg, user2.safe))
        client_stream(sock1, user1, room_num)
    elif puser == "exit":
        logout(user1)
    else:
        main_menu_handler(sock1, user1)

def client_stream(c, user, room):
    response = ""
    room_recent = get_roomchat(user, room, c)
    room_recent = salsa_encrypt(room_recent, user.safe)
    send(c, room_recent)
    while True:
        msg = recv(c, 2048)
        msg = salsa_decrypt(msg, user.safe)
        msg = msg.rstrip("\r\n")
        if msg == "\r\n":
            continue
        elif msg == "\n":
            continue
        elif msg == "exit":
            leave_room(user.name, room)
            logout(user)
            break
        elif msg == "leave":
            leave_room(user.name, room)
            main_menu_handler(c, user)
        elif msg == "otr":
            for speakeasy in StreamServer.private_rooms:
                if speakeasy.name == room:
                    msg = "has enabled off the record!"
                    append_msg(user.name, msg, room)
                    otr(user.name, room)
        elif "accept" in msg:
            cmd = msg.split(" ")
            if len(cmd) > 1:
                rm = cmd.pop(1)
                if num_check(rm) == True:
                    proom = int(rm)
                    if proom in StreamServer.rooms:
                        leave_room(user.name, room)
                        client_stream(c, user, proom)
                    else:
                        response = "Room or invite does not exist"
                        response = salsa_encrypt(response, user.safe)
                        send(c, response)
                        
                else:
                    response = "Room or invite does not exist"
                    response = salsa_encrypt(response, user.safe)
                    send(c, response)
            else:
                response = "Room or invite does not exist"
                response = salsa_encrypt(response, user.safe)
                send(c, response)
        elif msg == "refresh":
            response = get_roomchat(user, room, c)
            response = salsa_encrypt(response, user.safe)
            send(c, response)
        else:
            if msg != "":
                append_msg(user.name, msg, room)
    logout(user)
    c.close()

def auth_handler(c):
    client_id = recv(c, 16)
    client_id = b64decode(client_id)
    if client_id == univeral_id:
        send(c, b64encode(StreamServer.public_key))
        session_pkg = recv(c, 256)
        session_pkg = rsa_decrypt(session_pkg, StreamServer.private_safe)
        username, passw, session_key = process_auth_pkg(session_pkg)
        if validate_creds(username,passw) == 1 and username not in stream_users_online and len(session_key) == 32:
            user = User(username, session_key)
            stream_users_online[username] = user
            online_sockets[username] = c
            main_menu_handler(c,user)
        else:
            c.close()
    else:
        c.close()

class Server:
    def __init__(self, host, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((host, port))
        print "StreamServer ready!"
    key = gen_session_key()
    safe = libnacl.secret.SecretBox(key)
    key = ""
    private_rooms = []
    rooms = { 1:'general', 2:'tech', 3:'stream', 9:'private' }
    private_safe = gen_server_keypair()
    public_key = private_safe.pk
    stream = Room("stream", stream_contents, False, [])
    tech = Room("tech", tech_contents, False, [])
    general = Room("general", general_contents, False, [])

    def listen(self, num):
        self.s.listen(num)
        while True:
            c, addr = self.s.accept()
            threading.Thread(target=auth_handler, args=(c,)).start()
        
StreamServer = Server(host, port)
StreamServer.listen(5)
