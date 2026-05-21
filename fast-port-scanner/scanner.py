import socket
from colorama import Fore

open_ports = []

def scan_port(target, port, timeout):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(timeout)

        result = sock.connect_ex((target, port))

        if result == 0:

            banner = ""

            try:
                sock.send(b"HELLO\r\n")
                banner = sock.recv(1024).decode().strip()

            except:
                banner = "No Banner"

            output = f"[OPEN] Port {port} | {banner}"

            print(Fore.GREEN + output)

            open_ports.append(output)

        sock.close()

    except:
        pass