import socket

target = input("Target IP: ")

ports = [21,22,80,443,3306]

for port in ports:
    s = socket.socket()
    s.settimeout(1)

    result = s.connect_ex((target, port))

    if result == 0:
        print(f"[+] Port {port} open")

    s.close()