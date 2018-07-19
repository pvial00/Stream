# Stream is a fully encrypted "ephemeral" chat server.

Includes:
3 Static rooms (general, tech, stream)
Private chat rooms

Prerequisites:
libsodium
libnacl

# Setup:
By default Stream runs on TCP port 64666

Run python stream_adduser.py to add your first user and generate the password db file.

Next run python stream_server.py on the server of your choice.

Connect to the server by running python streamc.py <hostname>
