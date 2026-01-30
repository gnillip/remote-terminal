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


#connection
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((IP, PORT))

# encryption key
ENC_KEY = Fernet.generate_key()
fernet = Fernet(ENC_KEY)
client.send(ENC_KEY)

time.sleep(0.5)
# T_PASW check
client.send( fernet.encrypt(str(T_PASW_CHECK).encode()) )

time.sleep(0.5)
# H_PASW check
client.send( fernet.encrypt(H_PASW.encode()) )

# now the fun part :)
# aka the terminal using

while True:
    CMD = input("\n====================\n-> ")
    client.send( fernet.encrypt(CMD.encode()) )

    if CMD == "exit":
        client.close()
        break

    out = client.recv(8192)
    print(fernet.decrypt(out).decode())