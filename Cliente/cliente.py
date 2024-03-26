from Crypto.Random import get_random_bytes
from datetime import datetime
import socket
import hmac
import ssl
import re

def ask_username():
    username = input("Please, insert an username: ")
    if username == '':
        print('You must enter a username')
    return username


def ask_password():
    def verify_password(password):
        if len(password) < 8:
            print("The password is too short.")
            return False
        if not re.search(r'[a-z]', password):
            print("The password has no lower case character")
            return False
        if not re.search(r'[A-Z]', password):
            print("The password has no upper case character")
            return False
        if not re.search(r'[0-9]', password):
            print("The password has no number")
            return False
        if not re.search(r'[!@#$%^&*()\-_=+{};:,<.>]', password):
            print("The password has no special character (!@#$%^&*()\-_=+{};:,<.>).")
            return False
        return True
    password = input("Please, insert a valid password.\nMinimum requirements:\n    - At least 8 characters\n    - One lower case and one upper case character\n    - One number\n    - One special character(!@#$%^&*()\-_=+{};:,<.>)\nInsert password: ")
    if verify_password(password):
        return password
    else:
        return ask_password()

def ask_message():
    message = input("Please enter a message: ")
    if message == '':
        print('You must enter a message')
        return ask_message()
    return message

def create_mac(msg, key):
    mac = hmac.new(key, msg.encode('utf-8'), digestmod='sha256')
    return mac

def create_message():
    username = ask_username()
    password = ask_password()
    message = ask_message()
    nonce = get_random_bytes(32).hex()
    date = datetime.now().strftime('%d/%m/%Y-%H:%M')
    msg = str(username) + ' ' + str(password) + ' ' + str(message) + ' ' + str(date) + ' ' + str(nonce)
    return msg

def cliente_ssl():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 3030))
    #client_socket.connect(('192.168.14.38', 3030))
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.load_cert_chain(certfile="Storage/client.crt", keyfile="Storage/client.key", password='asAS12!"')
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="Storage/server.crt")
    secure_socket = context.wrap_socket(client_socket, server_hostname='localhost')

    try:
        with open('Storage/mac.key', 'rb') as f:
            content = f.read()
        mac_key = content
        msg = create_message()
        mac = create_mac(msg, mac_key).digest()
        data = msg.encode('utf-8') + b' --|-- ' + mac
        secure_socket.sendall(data)
        data = secure_socket.recv(1024)
        print("Mensaje del servidor:", data.decode())

    finally:
        secure_socket.close()

if __name__ == "__main__":
    cliente_ssl()