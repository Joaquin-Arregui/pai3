from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto import Random
from datetime import datetime
import random
import socket
import string
import hmac
import ssl

def generate_random_string(length, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(length))

def generate_random_username():
    length = random.randint(5, 10)
    return generate_random_string(length)

def generate_random_password():
    length = random.randint(8, 12)
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+{};:,<.>"
    password = generate_random_string(length, chars)
    while (not any(c.islower() for c in password) or
           not any(c.isupper() for c in password) or
           not any(c.isdigit() for c in password) or
           not any(c in "!@#$%^&*()-_=+{};:,<.>" for c in password)):
        password = generate_random_string(length, chars)
    return password

def generate_random_message():
    words = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit"]
    length = random.randint(5, 10)
    return ' '.join(random.choice(words) for _ in range(length))

def create_message():
    username = generate_random_username()
    password = generate_random_password()
    message = generate_random_message()
    nonce = get_random_bytes(32).hex()
    date = datetime.now().strftime('%d/%m/%Y-%H:%M')
    msg = str(username) + ' ' + str(password) + ' ' + str(message) + ' ' + str(date) + ' ' + str(nonce)
    return msg

def create_mac(msg, key):
    mac = hmac.new(key, msg.encode('utf-8'), digestmod='sha256')
    return mac

def cliente_ssl(i):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 3030))
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
        print("Mensaje del servidor:", data.decode() + ' \nMessage: ' + i)
        return data.decode()

    finally:
        secure_socket.close()

if __name__ == "__main__":
    res = 0
    for i in range(300):
        print(f"Sending request {i+1}")
        response = cliente_ssl(str(i))
        if response == 'The data has been recieved succesfully':
            res += 1
    print('Succesful messages: ' + str(res))