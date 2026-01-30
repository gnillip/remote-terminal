import os, socket, datetime, subprocess
from cryptography.fernet import Fernet

if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")

PORT = 1337
TODAY = datetime.date.today().strftime("%Y-%m-%d")
MY_PASW = input("Your Password for the session: ") or "remote-terminal"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", PORT))
server.listen()

while True:
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
    T_PASW = fernet.decrypt( conn.recv(1024) )
    if int(T_PASW.decode()) != T_PASW_CHECK:
        conn.close()
        print(addr[0], " Wrong T_PASW_CHECK")
        continue
    
    # Now my pasw, which i made
    H_PASW = fernet.decrypt( conn.recv(1024) ).decode()
    if H_PASW != MY_PASW:
        conn.close()
        print(addr[0], "Wrong MY_PASW")
        continue
    
    # now, finally, the terminal logic :)
    while True:
        CMD = fernet.decrypt( conn.recv(4096) ).decode()

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
                result = subprocess.run(CMD, shell=True, capture_output=True, text=True)
                out = result.stdout + result.stderr
                if not out:
                    out = "OK [command w/o output]"
            except Exception as e:
                out = str(e)
                print("Exception: ", e)
            
            conn.send( fernet.encrypt(out.encode()) )