import os, socket, datetime, time, hashlib
from cryptography.fernet import Fernet

if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")

PORT = 1337
IP = input("IP: ")
H_PASW = input("Password: ")


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data


#connection
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((IP, PORT))

# encryption key
ENC_KEY = Fernet.generate_key()
fernet = Fernet(ENC_KEY)
client.send(ENC_KEY)

time.sleep(0.5)
# T_PASW check
nonce_length = int.from_bytes(recv_exact(client, 4), "big")
nonce = fernet.decrypt( recv_exact(client, nonce_length) ).decode()

T_PASW = "Rem-Ter!g"
T_PASW_CHECK = hashlib.sha256((nonce+T_PASW).encode()).hexdigest()

data = fernet.encrypt(str(T_PASW_CHECK).encode())
client.sendall(len(data).to_bytes(4, "big") + data)

time.sleep(0.5)
# H_PASW check
data = fernet.encrypt(H_PASW.encode())
client.sendall(len(data).to_bytes(4, "big") + data)

# now the fun part :)
# aka the terminal using

while True:
    CMD = input("\n====================\n-> ")
    data = fernet.encrypt(CMD.encode())
    client.sendall(len(data).to_bytes(4, "big") + data)

    if CMD == "exit":
        client.close()
        break
    elif CMD.startswith("recv "):
        DATEINAME = CMD.replace("recv ", "")
        recv_len = int.from_bytes(recv_exact(client, 4), "big")
        DATEIINHALT = fernet.decrypt( recv_exact(client, recv_len) )
        with open(DATEINAME, "wb") as data:
            data.write(DATEIINHALT)
    elif CMD.startswith("send "):
        try:
            DATEINAME = CMD.replace("send ", "")
            DATEIINHALT = open(DATEINAME, "rb").read()
            DATEI_VER = fernet.encrypt(DATEIINHALT)
            client.sendall(len(DATEI_VER).to_bytes(4, "big") + DATEI_VER)
        except FileNotFoundError:
            DATEI_VER = b"The File wasn't found on the client."
            client.sendall(len(DATEI_VER).to_bytes(4, "big") + DATEI_VER)

    length = int.from_bytes(recv_exact(client, 4), "big")
    out = fernet.decrypt(recv_exact(client, length)).decode()
    print(out)