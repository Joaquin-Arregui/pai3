from datetime import datetime
import socket
import hmac
import ssl

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
