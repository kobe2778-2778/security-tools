import argparse
import threading
from tqdm import tqdm
from scanner import scan_port, open_ports

parser = argparse.ArgumentParser(
    description="Fast Multi-threaded Port Scanner"
)

parser.add_argument(
    "target",
    help="Target IP or Domain"
)

parser.add_argument(
    "-s",
    "--start",
    type=int,
    default=1,
    help="Start Port"
)

parser.add_argument(
    "-e",
    "--end",
    type=int,
    default=1024,
    help="End Port"
)

parser.add_argument(
    "-t",
    "--timeout",
    type=float,
    default=1,
    help="Socket Timeout"
)

args = parser.parse_args()

target = args.target
start_port = args.start
end_port = args.end
timeout = args.timeout

print(f"\nScanning Target: {target}")
print(f"Port Range: {start_port}-{end_port}\n")

threads = []

for port in tqdm(range(start_port, end_port + 1)):

    thread = threading.Thread(
        target=scan_port,
        args=(target, port, timeout)
    )

    threads.append(thread)

    thread.start()

for thread in threads:
    thread.join()

print("\nScan Complete.")

if open_ports:

    with open("results.txt", "w") as file:

        for port in open_ports:
            file.write(port + "\n")

    print("Results saved to results.txt")

else:
    print("No open ports found.")