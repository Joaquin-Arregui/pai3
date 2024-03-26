from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as padding_RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto import Random
from datetime import datetime
import hashlib
import socket
import base64
import hmac
import ssl
import re

def createHash(input_string):
    hash_object = hashlib.sha256(input_string)
    hash_digest = hash_object.digest()
    base64_encoded_hash = base64.b64encode(hash_digest)
    base64_string = base64_encoded_hash.decode('utf-8')
    return base64_string

def encrypt(data, key):
    if isinstance(data, str):
        data = data.encode()
    iv = get_random_bytes(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

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

def create_key():
    random = Random.new().read
    RSAkey = RSA.generate(2048, random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()
    return public, private

def decrypt_RSA(encrypted_data, key):
    private_key = serialization.load_pem_private_key(
        key,
        password=None,
        backend=default_backend()
    )
    
    decrypted_message = private_key.decrypt(
        encrypted_data,
        padding_RSA.OAEP(
            mgf=padding_RSA.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

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