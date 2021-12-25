from functools import partial
from os import urandom
from socket import create_connection

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key


def read(sock, length):
    result = b''
    while len(result) < length:
        result += sock.recv(length - len(result))
    return result


def read_int(sock, length):
    return int.from_bytes(read(sock, length), 'big')


def write(sock, data):
    sock.sendall(data)


def pack_credentials(data):
    data = data.encode('utf-8') + b'\x00'
    if len(data) < 64:
        data += urandom(64 - len(data))
    else:
        data = data[:64]
    return data


def connect(host, port, username, password, public_key=None):
    sock = create_connection((host, port))

    # Standard VNC version number exchange
    write(sock, b'RFB 003.889\n')
    read(sock, 12)

    # Standard VNC auth types exchange
    read(sock, read_int(sock, 1))
    write(sock, b'\x21')

    # ---- begin Apple VNC auth ----
    if public_key is None:
        write(sock, b'\x00\x00\x00\x0a'  # packet length
                    b'\x01\x00'          # packet version
                    b'RSA1'              # host key algorithm
                    b'\x00\x00'          # has credentials? (no)
                    b'\x00\x00')         # has AES key? (no)
        read(sock, 4)  # packet length
        read(sock, 2)  # packet version
        public_key_length = read_int(sock, 4)
        public_key = load_der_public_key(read(sock, public_key_length))
        read(sock, 1)  # unknown (zero)

    aes_key = urandom(16)
    aes_enc = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor().update
    pub_enc = partial(public_key.encrypt, padding=padding.PKCS1v15())

    write(sock, b'\x00\x00\x01\x8a'  # packet length
                b'\x01\x00'          # packet version
                b'RSA1'              # host key algorithm
                b'\x00\x01' +        # has credentials? (yes)
                aes_enc(pack_credentials(username) + pack_credentials(password)) +
                b'\x00\x01' +        # has aes key? (yes)
                pub_enc(aes_key))
    read(sock, 4)  # unknown (all zeroes)
    # ---- end Apple VNC auth ----

    # Standard VNC auth response
    if read_int(sock, 4) != 0:
        raise PermissionError("Authentication failed.")

    # Standard VNC client init etc
    write(sock, b'\x01')


connect('localhost', 5900, 'username', 'password')
