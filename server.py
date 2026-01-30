import os, socket, datetime
from cryptography.fernet import Fernet

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
    
    # Now my pasw, which i made
    H_PASW = fernet.decrypt( conn.recv(1024) ).decode()
    if H_PASW != MY_PASW:
        conn.close()
        print(addr[0], "Wrong MY_PASW")
    
    # now, finally, the terminal logic :)
    while True:
        CMD = fernet.decrypt( conn.recv(4096) ).decode()

        if CMD.startswith("cd "):
            os.chdir(CMD.replace("cd ", ""))
        elif CMD == "exit":
            conn.close()
            print(addr[0], " typed exit")
            break
        else:
            os.system(CMD)