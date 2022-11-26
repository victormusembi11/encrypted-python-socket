import socket
import threading
import rsa
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-H', '--host', type=str, help='enter server ip address')
parser.add_argument('-p', '--port', type=int, help='enter server port address')
args = parser.parse_args()

pub_key, priv_key = rsa.newkeys(1024)
conn_pub_key = None

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((args.host, args.port))
print('connection to server successful...')

# Exchange public keys with connected client
s.send(bytes(pub_key.save_pkcs1('PEM')))
conn_pub_key = rsa.PublicKey.load_pkcs1(s.recv(1024))


def send_msg(conn: socket.socket):
    while True:
        msg = input('> ')

        encrypt_msg = rsa.encrypt(msg.encode(), conn_pub_key)
        conn.send(encrypt_msg)
        print(f'sent: {msg}\n', end='')


def recv_msg(conn: socket.socket):
    while True:
        msg = conn.recv(1024)
        decrypt_msg = rsa.decrypt(msg, priv_key).decode()
        print(f'recv: {decrypt_msg}\n> ', end='')


threading.Thread(target=send_msg, args=(s, )).start()
threading.Thread(target=recv_msg, args=(s, )).start()
