import socket
from colorama import Fore, init

init()

domain = input("Target Domain: ")

with open("subdomains.txt") as f:
    subdomains = f.read().splitlines()

for sub in subdomains:

    url = f"{sub}.{domain}"

    try:
        ip = socket.gethostbyname(url)

        print(Fore.GREEN + f"[FOUND] {url} --> {ip}")

    except:
        pass