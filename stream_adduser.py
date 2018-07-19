import hashlib, os, sys, getpass
import libnacl, libnacl.secret

filename = "stream.db"
key = "5%9Bd@3gUi$5KPqS7$TBm9201A35%bB#"
box = libnacl.secret.SecretBox(key)

try:
    mode = sys.argv[1]
except IndexError as ier:
    pass
else:
    passfile = open(filename, "r")
    contents = passfile.read()
    contents = box.decrypt(contents)
    passfile.close()
    sys.stdout.write(contents)
    sys.exit(0)

def get_input():
    user = raw_input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    hashed_pass = libnacl.crypto_hash(password)
    entry = user + ":" + hashed_pass + "\n"
    return entry

if os.path.isfile(filename) == 1:
    passfile = open(filename, "r")
    contents = passfile.read()
    passfile.close()
    contents = box.decrypt(contents)
    entry = get_input()
    contents += entry
    contents = box.encrypt(contents)
    passfile = open(filename, "w")
    passfile.write(contents)
    passfile.close()
else:
    entry = get_input()
    passfile = open(filename, "w")
    contents = box.encrypt(entry)
    passfile.write(contents)
    passfile.close()
