import requests

with open("urls.txt", "r") as f:
    urls = f.read().splitlines()

for url in urls:
    try:
        response = requests.get(url, timeout=3)

        print(f"[{response.status_code}] {url}")

    except:
        print(f"[FAIL] {url}")