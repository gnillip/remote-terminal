import os, socket, datetime, time
from cryptography.fernet import Fernet

if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")

PORT = 1337
IP = input("IP: ")
H_PASW = input("Password: ")

TODAY = datetime.date.today().strftime("%Y-%m-%d")
T_PASW_CHECK = 0
T_PASW_CHECK_list = TODAY.split("-")
for i in T_PASW_CHECK_list:
    T_PASW_CHECK += int(i)


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

    length = int.from_bytes(recv_exact(client, 4), "big")
    out = fernet.decrypt(recv_exact(client, length)).decode()
    print(out)