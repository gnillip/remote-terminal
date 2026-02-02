import os, socket, time, hashlib
import DH_key_exchange as DH_KEY

if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")

PORT = 1337
IP = input("IP: ")
H_PASW = input("Password: ")
T_PASW = ["Rem-Ter!g", "Terry#Remus-g", "TR_!g", "G-2e+tr"]


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
p = int.from_bytes(client.recv(8192), "big")
time.sleep(1)
g = int.from_bytes(client.recv(4096), "big")

fernet = DH_KEY.DH(p, g)
their_pub_key = int.from_bytes(client.recv(4096), "big")

client.send(fernet.public_key.to_bytes(len(str(fernet.public_key)), "big"))
fernet.generate_shared_secret(their_pub_key)
fernet.generate_AES_key()

time.sleep(0.5)
# T_PASW check
for pasw in T_PASW:
    nonce_length = int.from_bytes(recv_exact(client, 4), "big")
    nonce = fernet.decrypt( recv_exact(client, nonce_length) ).decode()

    T_PASW_CHECK = hashlib.sha256((nonce[:10]+pasw).encode()).hexdigest()

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