import os, socket, datetime, subprocess
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
MY_PASW = input("Your Password for the session: ") or "remote-terminal"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", PORT))
server.listen()

while True:
    try:
        conn, addr = server.accept()
        print("Verbindung von: ", addr)

        # encryption key
        ENC_KEY = conn.recv(44)
        fernet = Fernet(ENC_KEY)

        # Check with time added together is the same, as in the client
        # (other people dont know, that i use this as veryfying)
        T_PASW_CHECK_list = TODAY.split("-")
        T_PASW_CHECK = 0
        for i in T_PASW_CHECK_list:
            T_PASW_CHECK += int(i)
        length = int.from_bytes(recv_exact(conn, 4), "big")
        T_PASW = fernet.decrypt(recv_exact(conn, length))
        if int(T_PASW.decode()) != T_PASW_CHECK:
            conn.close()
            print(addr[0], " Wrong T_PASW_CHECK")
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
                    conn.send( fernet.encrypt(b"OK [command w/o output]") )
                except PermissionError:
                    conn.send( fernet.encrypt(b"You don't have Permission to go there!") )
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