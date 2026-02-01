import os, socket, datetime, subprocess, hashlib, random, string
from cryptography.fernet import Fernet

if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data


PORT = 1337
TODAY = datetime.date.today().strftime("%Y-%m-%d")
MY_PASW = open("PASSWORD.txt", "r").read()
SHANONCE_PASW = ["Rem-Ter!g", "Terry#Remus-g", "TR_!g", "G-2e+tr"]

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", PORT))
server.listen()

print("server running...")
while True:
    try:
        conn, addr = server.accept()
        print("Verbindung von: ", addr)

        # encryption key
        ENC_KEY = conn.recv(44)
        fernet = Fernet(ENC_KEY)

        # send something, client sends sha256(something+Password)
        T_PASW_CHECK = True
        for pasw in SHANONCE_PASW:
            nonce = "".join(random.choice(string.ascii_letters) for _ in range(14))
            conn.sendall(len(fernet.encrypt(nonce.encode())).to_bytes(4, "big") + fernet.encrypt(nonce.encode()))
            T_PASW = hashlib.sha256((nonce[:10]+pasw).encode()).hexdigest()
            U_PASW = fernet.decrypt( recv_exact(conn, int.from_bytes(recv_exact(conn, 4), "big")) ).decode()

            if U_PASW != T_PASW:
                conn.close()
                print(addr[0], f" Wrong T_PASW ({SHANONCE_PASW.index(pasw)}/{len(SHANONCE_PASW)})")
                T_PASW_CHECK = False
                break
        
        if not T_PASW_CHECK:
            continue
        
        # Now my pasw, which i made
        length = int.from_bytes(recv_exact(conn, 4), "big")
        H_PASW = fernet.decrypt(recv_exact(conn, length)).decode()
        if H_PASW != MY_PASW:
            conn.close()
            print(addr[0], "Wrong MY_PASW")
            continue
        
        # now, finally, the terminal logic :)
        while True:
            length = int.from_bytes(recv_exact(conn, 4), "big")
            CMD = fernet.decrypt(recv_exact(conn, length)).decode()

            if CMD.startswith("cd "):
                try:
                    os.chdir(CMD.replace("cd ", ""))
                    msg = fernet.encrypt(b"OK [command w/o output]")
                    conn.sendall(len(msg).to_bytes(4, "big") + msg)
                except PermissionError:
                    msg = fernet.encrypt(b"You don't have Permission to go there!")
                    conn.sendall(len(msg).to_bytes(4, "big") + msg)
            elif CMD.startswith("recv "):
                try:
                    DATEINAME = CMD.replace("recv ", "")
                    DATEIINHALT = open(DATEINAME, "rb").read()
                    DATEI_VER = fernet.encrypt(DATEIINHALT)
                    conn.sendall(len(DATEI_VER).to_bytes(4, "big") + DATEI_VER)

                    msg = fernet.encrypt(b"OK [command w/o output]")
                    conn.sendall(len(msg).to_bytes(4, "big") + msg)
                except FileNotFoundError:
                    conn.sendall(len("File not found.").to_bytes(4, "big") + "File not found.".encode())
            elif CMD.startswith("send "):
                DATEINAME = CMD.replace("send ", "")
                dateilänge = int.from_bytes(recv_exact(conn, 4), "big")
                DATEIINHALT = fernet.decrypt( recv_exact(conn, dateilänge) )
                with open(DATEINAME, "wb") as data:
                    data.write(DATEIINHALT)
                
                msg = fernet.encrypt(b"OK [command w/o output]")
                conn.sendall(len(msg).to_bytes(4, "big") + msg)
            elif CMD == "exit":
                conn.close()
                print(addr[0], " typed exit")
                break
            else:
                try:
                    result = subprocess.run(CMD, shell=True, capture_output=True, text=True, encoding="cp1252", errors="replace")
                    out = result.stdout + result.stderr
                    if not out:
                        out = "OK [command w/o output]"
                except Exception as e:
                    out = str(e)
                    print("Exception: ", e)
                
                data = fernet.encrypt(out.encode())
                conn.sendall(len(data).to_bytes(4, "big") + data)
    except KeyboardInterrupt:
        print("KeyboardInterrupt...")