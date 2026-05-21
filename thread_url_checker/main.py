import requests
import threading
from queue import Queue

q = Queue()

def check_url():
    while not q.empty():
        url = q.get()

        try:
            response = requests.get(url, timeout=3)

            print(f"[{response.status_code}] {url}")

        except:
            print(f"[FAIL] {url}")

        q.task_done()

with open("urls.txt", "r") as f:
    urls = f.read().splitlines()

for url in urls:
    q.put(url)

for i in range(10):
    t = threading.Thread(target=check_url)
    t.start()

q.join()