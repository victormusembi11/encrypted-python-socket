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


def socket_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((args.host, args.port))
    s.listen()
    print('listening for incoming connections...')
    return s


def accept_connection(s: socket.socket):
    global conn_pub_key

    conn, _ = s.accept()
    print('connection to client established...')

    # Exchange public keys with connected client
    conn.send(bytes(pub_key.save_pkcs1('PEM')))
    conn_pub_key = rsa.PublicKey.load_pkcs1(conn.recv(1024))
    return conn


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


s = socket_server()
conn = accept_connection(s)

threading.Thread(target=send_msg, args=(conn, )).start()
threading.Thread(target=recv_msg, args=(conn, )).start()
