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
import random
import socket
import string
import base64
import hmac
import ssl

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

def generate_random_string(length, chars=string.ascii_letters + string.digits):
    """Generate a random string of fixed length."""
    return ''.join(random.choice(chars) for _ in range(length))

def generate_random_username():
    """Generate a random username."""
    length = random.randint(5, 10)  # Example: usernames between 5 and 10 characters
    return generate_random_string(length)

def generate_random_password():
    """Generate a random password that meets the requirements."""
    length = random.randint(8, 12)  # Passwords between 8 and 12 characters
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+{};:,<.>"
    password = generate_random_string(length, chars)
    # Ensuring the password meets all requirements
    while (not any(c.islower() for c in password) or
           not any(c.isupper() for c in password) or
           not any(c.isdigit() for c in password) or
           not any(c in "!@#$%^&*()-_=+{};:,<.>" for c in password)):
        password = generate_random_string(length, chars)
    return password

def generate_random_message():
    """Generate a random message."""
    words = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit"]
    length = random.randint(5, 10)  # Example: messages between 5 and 10 words
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