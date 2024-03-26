from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as padding_RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Random import get_random_bytes
from datetime import datetime
import hashlib
import socket
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

def create_mac(msg, key):
    mac = hmac.new(key, msg.encode('utf-8'), digestmod='sha256')
    return mac

def get_nonce():
    with open('Storage/nonces.txt', 'r') as f:
        content = f.read()
    return content.split('\n')

def add_log(text):
    date = datetime.now()
    logname = date.strftime("%m-%y") + '.log'
    with open('logs/'+logname, 'a') as f:
        if text == 'The data has been recieved succesfully':
            f.write('+ Success\n')
        elif text == 'The data has been manipulated with a Man-in-the-middle Attack' or text == 'The data has been retained with a Man-in-the-middle Attack':
            f.write('- Man-In-The-Middle\n')
        elif text == 'The data message has been duplicated with a replay attack':
            f.write('- Replay\n')

def encrypt_RSA(data, key):
    public_key = serialization.load_pem_public_key(
        key,
        backend=default_backend()
    )
    encrypted_message = public_key.encrypt(
        data,
        padding_RSA.OAEP(
            mgf=padding_RSA.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def servidor_ssl():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 3030))
    #server_socket.bind(('0.0.0.0', 3030))
    server_socket.listen(1)
    nonce_list = get_nonce()
    print("Esperando conexiones...")

    while True:
        connection, client_address = server_socket.accept()
        try:
            print("Conexión aceptada de:", client_address)
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile="Storage/server.crt", keyfile="Storage/server.key", password='asAS12!"')
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile="Storage/client.pem")
            secure_connection = context.wrap_socket(connection, server_side=True)
            if True:
                data = secure_connection.recv(1024)
                if data:
                            parts = data.split(b' --|-- ')
                            msg = parts[0].decode('utf-8')
                            mac = parts[-1]
                            nonce = msg.split()[-1]
                            date = msg.split()[-2]
                            date_check = datetime.now().strftime('%d/%m/%Y-%H:%M')
                            with open('Storage/mac.key', 'rb') as f:
                                content = f.read()
                            key = content
                            mac_check = create_mac(msg, key).digest()
                            res = ''
                            
                            if date == date_check:
                                if nonce not in nonce_list:
                                    with open('Storage/nonces.txt', 'a') as f:
                                        f.write(nonce + '\n')
                                        nonce_list.append(nonce)
                                    if mac == mac_check:
                                        res = 'The data has been recieved succesfully'
                                    else:
                                        res = 'The data has been manipulated with a Man-in-the-middle Attack'
                                else:
                                    res = 'The data message has been duplicated with a replay attack'
                            else:
                                res = 'The data has been retained with a Man-in-the-middle Attack'
                            add_log(res)
                            secure_connection.sendall(res.encode('utf-8'))
                else:
                    add_log('The key has been manipulated')
            secure_connection.close()
        finally:
            if 'secure_connection' in locals():
                secure_connection.close()

if __name__ == "__main__":
    servidor_ssl()
